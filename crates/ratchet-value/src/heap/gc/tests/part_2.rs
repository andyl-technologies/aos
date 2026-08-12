//! GC-planning unit tests, part 2 of 5 (RFC-0007 §2 split, #9).
//!
//! Move-only line-boundary split of `gc/tests.rs`; no test changed.

use super::super::*;
use super::address;

#[test]
fn minor_gc_destination_placement_plan_rejects_invalid_alignment_metadata() {
    let young = address(0x1000);
    let survivor = MinorGcSurvivor {
        address: young,
        previous_survivals: 0,
        next_survivals: 1,
        action: MinorGcSurvivorAction::CopyToNursery,
    };
    let allocation_plan = MinorGcDestinationAllocationPlan {
        allocations: vec![MinorGcDestinationAllocation {
            survivor,
            size_bytes: 8,
            align: 0,
        }],
        nursery_bytes: 8,
        old_bytes: 0,
    };

    assert_eq!(
        MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan),
        Err(
            GenerationalGcError::InvalidMinorGcDestinationPlacementAlignment {
                generation: HeapGeneration::Young,
                align: 0,
            }
        )
    );
}

#[test]
fn minor_gc_relocation_destination_plan_materializes_offsets_from_bases() {
    let first_copy = address(0x1000);
    let promote = address(0x2000);
    let second_copy = address(0x3000);
    let nursery_base = address(0x9000);
    let old_base = address(0xa000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first_copy),
            ResolvedValueGeneration::young(promote),
            ResolvedValueGeneration::young(second_copy),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first_copy, 0),
            NurseryObjectAge::new(promote, 1),
            NurseryObjectAge::new(second_copy, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(second_copy, 8, 16),
            NurseryObjectLayout::new(promote, 40, 16),
            NurseryObjectLayout::new(first_copy, 24, 8),
        ],
    )
    .expect("allocation plan builds");
    let placement_plan = MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)
        .expect("placement plan builds");
    let bases = MinorGcDestinationBases::new(nursery_base, old_base);

    let destination_plan =
        MinorGcRelocationDestinationPlan::from_placement_plan(&plan, &placement_plan, bases)
            .expect("relocation destination plan builds");

    assert_eq!(bases.nursery(), nursery_base);
    assert_eq!(bases.old(), old_base);
    assert_eq!(destination_plan.len(), 3);
    assert!(!destination_plan.is_empty());
    assert_eq!(destination_plan.destinations()[0].source(), first_copy);
    assert_eq!(
        destination_plan.destinations()[0].destination(),
        nursery_base
    );
    assert_eq!(destination_plan.destinations()[1].source(), promote);
    assert_eq!(destination_plan.destinations()[1].destination(), old_base);
    assert_eq!(destination_plan.destinations()[2].source(), second_copy);
    assert_eq!(
        destination_plan.destinations()[2].destination(),
        address(0x9020)
    );

    let relocation_plan = destination_plan
        .relocation_plan(&plan)
        .expect("relocation plan builds");
    assert_eq!(relocation_plan.len(), 3);
    assert_eq!(relocation_plan.relocations()[0].source(), first_copy);
    assert_eq!(relocation_plan.relocations()[0].destination(), nursery_base);
    assert_eq!(
        relocation_plan.relocations()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(relocation_plan.relocations()[1].source(), promote);
    assert_eq!(relocation_plan.relocations()[1].destination(), old_base);
    assert_eq!(
        relocation_plan.relocations()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(relocation_plan.relocations()[2].source(), second_copy);
    assert_eq!(
        relocation_plan.relocations()[2].destination(),
        address(0x9020)
    );
}

#[test]
fn minor_gc_relocation_destination_plan_rejects_bad_materialized_addresses() {
    let first = address(0x1000);
    let second = address(0x2000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::young(second),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first, 0),
            NurseryObjectAge::new(second, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let overflow_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(first, 8, 8),
            NurseryObjectLayout::new(second, 8, 8),
        ],
    )
    .expect("overflow allocation plan builds");
    let overflow_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&overflow_allocation_plan)
            .expect("overflow placement plan builds");
    let overflow_base = address(usize::MAX & !POINTER_TAG_MASK);

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &plan,
            &overflow_placement_plan,
            MinorGcDestinationBases::new(overflow_base, address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationAddressOverflow {
                generation: HeapGeneration::Young,
                base: overflow_base,
                offset: 8,
            }
        )
    );

    let low_tag_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(first, 4, 4),
            NurseryObjectLayout::new(second, 8, 4),
        ],
    )
    .expect("low-tag allocation plan builds");
    let low_tag_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&low_tag_allocation_plan)
            .expect("low-tag placement plan builds");

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &plan,
            &low_tag_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(GenerationalGcError::LowTagBitsPresent {
            address_bits: 0x9004,
        })
    );

    let misaligned_base_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &plan,
        &[
            NurseryObjectLayout::new(first, 16, 16),
            NurseryObjectLayout::new(second, 8, 8),
        ],
    )
    .expect("misaligned-base allocation plan builds");
    let misaligned_base_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&misaligned_base_allocation_plan)
            .expect("misaligned-base placement plan builds");
    let misaligned_destination = address(0x9008);

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &plan,
            &misaligned_base_placement_plan,
            MinorGcDestinationBases::new(misaligned_destination, address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: first,
                generation: HeapGeneration::Young,
                destination: misaligned_destination,
                align: 16,
            }
        )
    );
}

#[test]
fn minor_gc_relocation_destination_plan_rejects_mismatched_placement_plan() {
    let young = address(0x1000);
    let copy_plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("copy minor GC plan builds");
    let promote_plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 1)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("promote minor GC plan builds");
    let copy_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &copy_plan,
        &[NurseryObjectLayout::new(young, 8, 8)],
    )
    .expect("copy allocation plan builds");
    let copy_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&copy_allocation_plan)
            .expect("copy placement plan builds");

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &promote_plan,
            &copy_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementActionMismatch {
                address: young,
                expected: MinorGcSurvivorAction::PromoteToOld,
                actual: MinorGcSurvivorAction::CopyToNursery,
            }
        )
    );

    let other = address(0x2000);
    let two_survivor_plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(young),
            ResolvedValueGeneration::young(other),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(young, 0),
            NurseryObjectAge::new(other, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("two-survivor minor GC plan builds");
    let reversed_plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(other),
            ResolvedValueGeneration::young(young),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(young, 0),
            NurseryObjectAge::new(other, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("reversed minor GC plan builds");
    let reversed_allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(
        &reversed_plan,
        &[
            NurseryObjectLayout::new(young, 8, 8),
            NurseryObjectLayout::new(other, 8, 8),
        ],
    )
    .expect("reversed allocation plan builds");
    let reversed_placement_plan =
        MinorGcDestinationPlacementPlan::from_allocation_plan(&reversed_allocation_plan)
            .expect("reversed placement plan builds");

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &two_survivor_plan,
            &reversed_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementSourceMismatch {
                expected: young,
                actual: other,
            }
        )
    );

    assert_eq!(
        MinorGcRelocationDestinationPlan::from_placement_plan(
            &two_survivor_plan,
            &copy_placement_plan,
            MinorGcDestinationBases::new(address(0x9000), address(0xa000)),
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementLengthMismatch {
                survivors: 2,
                placements: 1,
            }
        )
    );
}

#[test]
fn minor_gc_relocation_plan_maps_survivors_in_frontier_order() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");

    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(promote, promote_destination),
            MinorGcRelocationDestination::new(copy, copy_destination),
        ],
    )
    .expect("relocation plan builds");

    assert_eq!(relocation_plan.len(), 2);
    assert!(!relocation_plan.is_empty());
    assert_eq!(relocation_plan.relocations()[0].source(), copy);
    assert_eq!(
        relocation_plan.relocations()[0].destination(),
        copy_destination
    );
    assert_eq!(
        relocation_plan.relocations()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(relocation_plan.relocations()[1].source(), promote);
    assert_eq!(
        relocation_plan.relocations()[1].destination(),
        promote_destination
    );
    assert_eq!(
        relocation_plan.relocations()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        relocation_plan.relocations()[1].survivor(),
        plan.survivors()[1]
    );
}

#[test]
fn minor_gc_relocation_plan_rejects_incomplete_or_stale_metadata() {
    let young = address(0x1000);
    let other = address(0x2000);
    let destination = address(0x9000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");

    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(&plan, &[]),
        Err(GenerationalGcError::MissingMinorGcRelocationDestination { address: young })
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(young, destination),
                MinorGcRelocationDestination::new(young, address(0xa000)),
            ],
        ),
        Err(GenerationalGcError::DuplicateMinorGcRelocationSource { address: young })
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(young, destination),
                MinorGcRelocationDestination::new(other, destination),
            ],
        ),
        Err(GenerationalGcError::DuplicateMinorGcRelocationDestination {
            address: destination,
        },)
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(young, destination),
                MinorGcRelocationDestination::new(other, address(0xa000)),
            ],
        ),
        Err(GenerationalGcError::StaleMinorGcRelocationSource { address: other })
    );
}

#[test]
fn minor_gc_relocation_destination_plan_canonicalizes_explicit_destinations() {
    let first = address(0x1000);
    let second = address(0x2000);
    let first_destination = address(0x9000);
    let second_destination = address(0xb000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::young(second),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first, 0),
            NurseryObjectAge::new(second, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let explicit_destinations = [
        MinorGcRelocationDestination::new(second, second_destination),
        MinorGcRelocationDestination::new(first, first_destination),
    ];

    let destination_plan =
        MinorGcRelocationDestinationPlan::from_destinations(&plan, &explicit_destinations)
            .expect("explicit destination plan builds");

    assert_eq!(
        destination_plan.destinations(),
        &[
            MinorGcRelocationDestination::new(first, first_destination),
            MinorGcRelocationDestination::new(second, second_destination),
        ]
    );
    assert_eq!(
        destination_plan
            .relocation_plan(&plan)
            .expect("relocation map rebuilds")
            .relocations()
            .iter()
            .map(|relocation| relocation.destination())
            .collect::<Vec<_>>(),
        vec![first_destination, second_destination]
    );
}

#[test]
fn minor_gc_relocation_plan_rejects_destinations_in_from_space() {
    let first = address(0x1000);
    let second = address(0x2000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::young(second),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first, 0),
            NurseryObjectAge::new(second, 0),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");

    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(first, first),
                MinorGcRelocationDestination::new(second, address(0x9000)),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationInFromSpace {
                from: first,
                destination: first,
            }
        )
    );
    assert_eq!(
        MinorGcRelocationPlan::from_minor_gc_plan(
            &plan,
            &[
                MinorGcRelocationDestination::new(first, second),
                MinorGcRelocationDestination::new(second, address(0x9000)),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationInFromSpace {
                from: first,
                destination: second,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_schedules_relocations_with_layouts() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(copy, copy_destination),
            MinorGcRelocationDestination::new(promote, promote_destination),
        ],
    )
    .expect("relocation plan builds");

    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(promote, 40, 16),
            NurseryObjectLayout::new(copy, 24, 8),
        ],
    )
    .expect("object-copy plan builds");

    assert_eq!(copy_plan.len(), 2);
    assert!(!copy_plan.is_empty());
    assert_eq!(
        copy_plan.copies()[0].relocation(),
        relocation_plan.relocations()[0]
    );
    assert_eq!(copy_plan.copies()[0].source(), copy);
    assert_eq!(copy_plan.copies()[0].destination(), copy_destination);
    assert_eq!(
        copy_plan.copies()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        copy_plan.copies()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        copy_plan.copies()[0].relocated_value(),
        ResolvedValueGeneration::young(copy_destination)
    );
    assert_eq!(copy_plan.copies()[0].size_bytes(), 24);
    assert_eq!(copy_plan.copies()[0].align(), 8);
    assert_eq!(copy_plan.copies()[1].source(), promote);
    assert_eq!(copy_plan.copies()[1].destination(), promote_destination);
    assert_eq!(
        copy_plan.copies()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        copy_plan.copies()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(
        copy_plan.copies()[1].relocated_value(),
        ResolvedValueGeneration::old(promote_destination)
    );
    assert_eq!(copy_plan.copies()[1].size_bytes(), 40);
    assert_eq!(copy_plan.copies()[1].align(), 16);
}

#[test]
fn minor_gc_object_copy_plan_copies_bytes_into_destination_buffers() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::young(promote),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(copy, 0),
            NurseryObjectAge::new(promote, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(copy, copy_destination),
            MinorGcRelocationDestination::new(promote, promote_destination),
        ],
    )
    .expect("relocation plan builds");
    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(copy, 4, 4),
            NurseryObjectLayout::new(promote, 6, 2),
        ],
    )
    .expect("object-copy plan builds");
    let copy_source = [1, 2, 3, 4];
    let promote_source = [5, 6, 7, 8, 9, 10];
    let mut copy_destination_bytes = [0; 4];
    let mut promote_destination_bytes = [0; 6];
    let mut buffers = [
        MinorGcObjectByteCopyBuffer::new(
            copy,
            copy_destination,
            &copy_source,
            &mut copy_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            promote,
            promote_destination,
            &promote_source,
            &mut promote_destination_bytes,
        ),
    ];

    copy_plan
        .copy_into_buffers(&mut buffers)
        .expect("object bytes copy");

    assert_eq!(buffers[0].source(), copy);
    assert_eq!(buffers[0].destination(), copy_destination);
    assert_eq!(buffers[0].source_bytes(), copy_source);
    assert_eq!(buffers[0].destination_bytes(), copy_source);
    assert_eq!(buffers[1].source(), promote);
    assert_eq!(buffers[1].destination(), promote_destination);
    assert_eq!(buffers[1].source_bytes(), promote_source);
    assert_eq!(buffers[1].destination_bytes(), promote_source);

    let mut empty_buffers = [];
    MinorGcObjectCopyPlan::default()
        .copy_into_buffers(&mut empty_buffers)
        .expect("empty object-copy plan accepts empty buffers");
}

#[test]
fn minor_gc_object_copy_plan_rejects_stale_byte_copy_buffers() {
    let first = address(0x1000);
    let second = address(0x2000);
    let other = address(0x3000);
    let first_destination = address(0x9000);
    let second_destination = address(0xa000);
    let other_destination = address(0xb000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::young(second),
        ],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[
            NurseryObjectAge::new(first, 0),
            NurseryObjectAge::new(second, 1),
        ],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(first, first_destination),
            MinorGcRelocationDestination::new(second, second_destination),
        ],
    )
    .expect("relocation plan builds");
    let copy_plan = MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &[
            NurseryObjectLayout::new(first, 4, 4),
            NurseryObjectLayout::new(second, 4, 4),
        ],
    )
    .expect("object-copy plan builds");
    let first_source = [1, 2, 3, 4];
    let second_source = [5, 6, 7, 8];

    let mut short_destination = [0; 4];
    let mut short_buffers = [MinorGcObjectByteCopyBuffer::new(
        first,
        first_destination,
        &first_source,
        &mut short_destination,
    )];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut short_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopyBufferLengthMismatch {
                copies: 2,
                buffers: 1,
            }
        )
    );
    assert_eq!(short_buffers[0].destination_bytes(), [0; 4]);

    let mut mismatched_first_destination = [0; 4];
    let mut mismatched_second_destination = [0; 4];
    let mut mismatched_source_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            other,
            first_destination,
            &first_source,
            &mut mismatched_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            second_destination,
            &second_source,
            &mut mismatched_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut mismatched_source_buffers),
        Err(GenerationalGcError::MinorGcObjectByteCopySourceMismatch {
            index: 0,
            expected: first,
            actual: other,
        })
    );
    assert_eq!(mismatched_source_buffers[0].destination_bytes(), [0; 4]);
    assert_eq!(mismatched_source_buffers[1].destination_bytes(), [0; 4]);

    let mut mismatched_first_destination = [0; 4];
    let mut mismatched_second_destination = [0; 4];
    let mut mismatched_destination_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            first,
            first_destination,
            &first_source,
            &mut mismatched_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            other_destination,
            &second_source,
            &mut mismatched_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut mismatched_destination_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopyDestinationMismatch {
                index: 1,
                expected: second_destination,
                actual: other_destination,
            }
        )
    );
    assert_eq!(
        mismatched_destination_buffers[0].destination_bytes(),
        [0; 4]
    );
    assert_eq!(
        mismatched_destination_buffers[1].destination_bytes(),
        [0; 4]
    );

    let short_source = [1, 2, 3];
    let mut source_length_first_destination = [0; 4];
    let mut source_length_second_destination = [0; 4];
    let mut source_length_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            first,
            first_destination,
            &short_source,
            &mut source_length_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            second_destination,
            &second_source,
            &mut source_length_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut source_length_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopySourceLengthMismatch {
                index: 0,
                address: first,
                expected: 4,
                actual: 3,
            }
        )
    );
    assert_eq!(source_length_buffers[0].destination_bytes(), [0; 4]);
    assert_eq!(source_length_buffers[1].destination_bytes(), [0; 4]);

    let mut destination_length_first_destination = [0; 4];
    let mut destination_length_second_destination = [0; 3];
    let mut destination_length_buffers = [
        MinorGcObjectByteCopyBuffer::new(
            first,
            first_destination,
            &first_source,
            &mut destination_length_first_destination,
        ),
        MinorGcObjectByteCopyBuffer::new(
            second,
            second_destination,
            &second_source,
            &mut destination_length_second_destination,
        ),
    ];
    assert_eq!(
        copy_plan.copy_into_buffers(&mut destination_length_buffers),
        Err(
            GenerationalGcError::MinorGcObjectByteCopyDestinationLengthMismatch {
                index: 1,
                address: second_destination,
                expected: 4,
                actual: 3,
            }
        )
    );
    assert_eq!(destination_length_buffers[0].destination_bytes(), [0; 4]);
    assert_eq!(destination_length_buffers[1].destination_bytes(), [0; 3]);
}
