//! GC-planning unit tests, part 3 of 5 (RFC-0007 §2 split, #9).
//!
//! Move-only line-boundary split of `gc/tests.rs`; no test changed.

use super::super::*;
use super::address;

#[test]
fn minor_gc_object_copy_plan_rejects_bad_layout_metadata() {
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
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(young, destination)],
    )
    .expect("relocation plan builds");

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(&relocation_plan, &[]),
        Err(GenerationalGcError::MissingNurseryObjectLayout { address: young })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(young, 8, 8),
                NurseryObjectLayout::new(young, 16, 8),
            ],
        ),
        Err(GenerationalGcError::DuplicateNurseryObjectLayout { address: young })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[NurseryObjectLayout::new(young, 0, 8)],
        ),
        Err(GenerationalGcError::InvalidNurseryObjectSize {
            address: young,
            size_bytes: 0,
        })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[NurseryObjectLayout::new(young, 8, 3)],
        ),
        Err(GenerationalGcError::InvalidNurseryObjectAlignment {
            address: young,
            align: 3,
        })
    );
    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(young, 8, 8),
                NurseryObjectLayout::new(other, 16, 8),
            ],
        ),
        Err(GenerationalGcError::StaleNurseryObjectLayout { address: other })
    );

    let misaligned_destination = address(0x9008);
    let misaligned_relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(
            young,
            misaligned_destination,
        )],
    )
    .expect("misaligned relocation plan builds");

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &misaligned_relocation_plan,
            &[NurseryObjectLayout::new(young, 16, 16)],
        ),
        Err(
            GenerationalGcError::MinorGcRelocationDestinationAlignmentMismatch {
                address: young,
                generation: HeapGeneration::Young,
                destination: misaligned_destination,
                align: 16,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_rejects_overlapping_destination_ranges() {
    let first = address(0x1000);
    let second = address(0x2000);
    let first_destination = address(0x9000);
    let second_destination = address(0x9008);
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
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(first, first_destination),
            MinorGcRelocationDestination::new(second, second_destination),
        ],
    )
    .expect("relocation plan builds");

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(first, 16, 8),
                NurseryObjectLayout::new(second, 16, 8),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: first_destination,
                second_generation: HeapGeneration::Young,
                second: second_destination,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_rejects_cross_generation_destination_range_overlap() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0x9008);
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

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[
                NurseryObjectLayout::new(copy, 16, 8),
                NurseryObjectLayout::new(promote, 16, 8),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: copy_destination,
                second_generation: HeapGeneration::Old,
                second: promote_destination,
            }
        )
    );
}

#[test]
fn minor_gc_object_copy_plan_rejects_destination_source_range_overlap() {
    let young = address(0x1000);
    let destination = address(0x1008);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(young)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(young, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(young, destination)],
    )
    .expect("relocation plan builds");

    assert_eq!(
        MinorGcObjectCopyPlan::from_relocation_plan(
            &relocation_plan,
            &[NurseryObjectLayout::new(young, 16, 8)],
        ),
        Err(
            GenerationalGcError::MinorGcObjectCopyDestinationSourceRangeOverlap {
                source_address: young,
                destination,
            }
        )
    );
}

#[test]
fn minor_gc_forwarding_pointer_plan_maps_object_copies_to_forwarded_values() {
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
            NurseryObjectLayout::new(copy, 24, 8),
            NurseryObjectLayout::new(promote, 40, 16),
        ],
    )
    .expect("object-copy plan builds");

    let forwarding_plan = MinorGcForwardingPointerPlan::from_object_copy_plan(&copy_plan)
        .expect("forwarding plan builds");

    assert_eq!(forwarding_plan.len(), 2);
    assert!(!forwarding_plan.is_empty());
    assert_eq!(forwarding_plan.pointers()[0].copy(), copy_plan.copies()[0]);
    assert_eq!(forwarding_plan.pointers()[0].source(), copy);
    assert_eq!(
        forwarding_plan.pointers()[0].destination(),
        copy_destination
    );
    assert_eq!(
        forwarding_plan.pointers()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        forwarding_plan.pointers()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        forwarding_plan.pointers()[0].forwarded_value(),
        ResolvedValueGeneration::young(copy_destination)
    );
    assert_eq!(forwarding_plan.pointers()[1].source(), promote);
    assert_eq!(
        forwarding_plan.pointers()[1].destination(),
        promote_destination
    );
    assert_eq!(
        forwarding_plan.pointers()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(
        forwarding_plan.pointers()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(
        forwarding_plan.pointers()[1].forwarded_value(),
        ResolvedValueGeneration::old(promote_destination)
    );

    let empty_forwarding_plan =
        MinorGcForwardingPointerPlan::from_object_copy_plan(&MinorGcObjectCopyPlan::default())
            .expect("empty forwarding plan builds");
    assert_eq!(empty_forwarding_plan.len(), 0);
    assert!(empty_forwarding_plan.is_empty());
}

#[test]
fn minor_gc_forwarding_pointer_plan_installs_into_forwarding_slots() {
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
            NurseryObjectLayout::new(copy, 24, 8),
            NurseryObjectLayout::new(promote, 40, 16),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_plan = MinorGcForwardingPointerPlan::from_object_copy_plan(&copy_plan)
        .expect("forwarding plan builds");
    let mut slots = [
        MinorGcForwardingSlot::new(copy),
        MinorGcForwardingSlot::new(promote),
    ];

    forwarding_plan
        .install_into_slots(&mut slots)
        .expect("forwarding slots install");

    assert_eq!(slots[0].source(), copy);
    assert_eq!(
        slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::young(copy_destination))
    );
    assert!(!slots[0].is_empty());
    assert_eq!(slots[1].source(), promote);
    assert_eq!(
        slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::old(promote_destination))
    );
    assert!(!slots[1].is_empty());
}

#[test]
fn minor_gc_forwarding_pointer_plan_rejects_stale_forwarding_slots() {
    let first = address(0x1000);
    let second = address(0x2000);
    let first_destination = address(0x9000);
    let second_destination = address(0xa000);
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
            NurseryObjectLayout::new(first, 8, 8),
            NurseryObjectLayout::new(second, 16, 16),
        ],
    )
    .expect("object-copy plan builds");
    let forwarding_plan = MinorGcForwardingPointerPlan::from_object_copy_plan(&copy_plan)
        .expect("forwarding plan builds");

    let mut short_slots = [MinorGcForwardingSlot::new(first)];
    let unchanged_short_slots = short_slots;
    assert_eq!(
        forwarding_plan.install_into_slots(&mut short_slots),
        Err(
            GenerationalGcError::MinorGcForwardingPointerSlotLengthMismatch {
                pointers: 2,
                slots: 1,
            }
        )
    );
    assert_eq!(short_slots, unchanged_short_slots);

    let mut mismatched_slots = [
        MinorGcForwardingSlot::new(second),
        MinorGcForwardingSlot::new(first),
    ];
    let unchanged_mismatched_slots = mismatched_slots;
    assert_eq!(
        forwarding_plan.install_into_slots(&mut mismatched_slots),
        Err(
            GenerationalGcError::MinorGcForwardingPointerSlotSourceMismatch {
                index: 0,
                expected: first,
                actual: second,
            }
        )
    );
    assert_eq!(mismatched_slots, unchanged_mismatched_slots);

    let mut occupied_slots = [
        MinorGcForwardingSlot::new(first),
        MinorGcForwardingSlot::with_forwarded_value(
            second,
            ResolvedValueGeneration::young(first_destination),
        ),
    ];
    let unchanged_occupied_slots = occupied_slots;
    assert_eq!(
        forwarding_plan.install_into_slots(&mut occupied_slots),
        Err(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
            index: 1,
            address: second,
            actual: ResolvedValueGeneration::young(first_destination),
        })
    );
    assert_eq!(occupied_slots, unchanged_occupied_slots);
}

#[test]
fn minor_gc_reference_rewrite_plan_maps_young_slots_through_relocations() {
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

    let rewrite_plan = MinorGcReferenceRewritePlan::from_references(
        &relocation_plan,
        [
            ResolvedValueGeneration::Inline,
            ResolvedValueGeneration::old(address(0x3000)),
            ResolvedValueGeneration::young(copy),
            ResolvedValueGeneration::permanent(address(0x4000)),
            ResolvedValueGeneration::young(promote),
            ResolvedValueGeneration::young(copy),
        ],
    )
    .expect("rewrite plan builds");

    assert_eq!(rewrite_plan.len(), 3);
    assert!(!rewrite_plan.is_empty());
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 2);
    assert_eq!(rewrite_plan.rewrites()[0].source(), copy);
    assert_eq!(rewrite_plan.rewrites()[0].destination(), copy_destination);
    assert_eq!(
        rewrite_plan.rewrites()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        rewrite_plan.rewrites()[0].replacement(),
        ResolvedValueGeneration::young(copy_destination)
    );
    assert_eq!(rewrite_plan.rewrites()[1].slot(), 4);
    assert_eq!(rewrite_plan.rewrites()[1].source(), promote);
    assert_eq!(
        rewrite_plan.rewrites()[1].destination(),
        promote_destination
    );
    assert_eq!(
        rewrite_plan.rewrites()[1].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(
        rewrite_plan.rewrites()[1].replacement(),
        ResolvedValueGeneration::old(promote_destination)
    );
    assert_eq!(rewrite_plan.rewrites()[2].slot(), 5);
    assert_eq!(rewrite_plan.rewrites()[2].source(), copy);
    assert_eq!(
        rewrite_plan.rewrites()[2].replacement(),
        ResolvedValueGeneration::young(copy_destination)
    );
}

#[test]
fn minor_gc_reference_rewrite_plan_applies_to_reference_slots() {
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
    let mut references = vec![
        ResolvedValueGeneration::Inline,
        ResolvedValueGeneration::young(copy),
        ResolvedValueGeneration::old(address(0x3000)),
        ResolvedValueGeneration::young(promote),
        ResolvedValueGeneration::young(copy),
    ];
    let rewrite_plan =
        MinorGcReferenceRewritePlan::from_references(&relocation_plan, references.clone())
            .expect("rewrite plan builds");

    rewrite_plan
        .apply_to_references(&mut references)
        .expect("rewrites apply");

    assert_eq!(
        references,
        [
            ResolvedValueGeneration::Inline,
            ResolvedValueGeneration::young(copy_destination),
            ResolvedValueGeneration::old(address(0x3000)),
            ResolvedValueGeneration::old(promote_destination),
            ResolvedValueGeneration::young(copy_destination),
        ]
    );
}

#[test]
fn minor_gc_reference_rewrite_plan_rejects_stale_or_missing_slots() {
    let first = address(0x1000);
    let second = address(0x2000);
    let first_destination = address(0x9000);
    let second_destination = address(0xa000);
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
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[
            MinorGcRelocationDestination::new(first, first_destination),
            MinorGcRelocationDestination::new(second, second_destination),
        ],
    )
    .expect("relocation plan builds");
    let original_references = vec![
        ResolvedValueGeneration::young(first),
        ResolvedValueGeneration::young(second),
    ];
    let rewrite_plan =
        MinorGcReferenceRewritePlan::from_references(&relocation_plan, original_references.clone())
            .expect("rewrite plan builds");

    let mut stale_references = original_references.clone();
    stale_references[1] = ResolvedValueGeneration::Inline;
    assert_eq!(
        rewrite_plan.apply_to_references(&mut stale_references),
        Err(GenerationalGcError::MinorGcReferenceRewriteSlotMismatch {
            slot: 1,
            expected: second,
            actual: ResolvedValueGeneration::Inline,
        })
    );
    assert_eq!(
        stale_references,
        [
            ResolvedValueGeneration::young(first),
            ResolvedValueGeneration::Inline,
        ]
    );

    let mut short_references = vec![ResolvedValueGeneration::young(first)];
    assert_eq!(
        rewrite_plan.apply_to_references(&mut short_references),
        Err(GenerationalGcError::MinorGcReferenceRewriteSlotOutOfBounds { slot: 1, slots: 1 })
    );
    assert_eq!(short_references, [ResolvedValueGeneration::young(first)]);
}

#[test]
fn minor_gc_reference_rewrite_plan_rejects_unplanned_young_references() {
    let planned = address(0x1000);
    let missing = address(0x2000);
    let destination = address(0x9000);
    let plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(planned)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(planned, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("minor GC plan builds");
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(
        &plan,
        &[MinorGcRelocationDestination::new(planned, destination)],
    )
    .expect("relocation plan builds");

    assert_eq!(
        MinorGcReferenceRewritePlan::from_references(
            &relocation_plan,
            [
                ResolvedValueGeneration::old(address(0x3000)),
                ResolvedValueGeneration::young(missing),
            ],
        ),
        Err(GenerationalGcError::MissingMinorGcReferenceRelocation { address: missing })
    );
    assert_eq!(
        MinorGcReferenceRewritePlan::from_references(
            &relocation_plan,
            [
                ResolvedValueGeneration::Inline,
                ResolvedValueGeneration::old(address(0x4000)),
                ResolvedValueGeneration::permanent(address(0x5000)),
            ],
        )
        .expect("non-young references need no rewrites")
        .rewrites(),
        &[]
    );
}

#[test]
fn minor_gc_remembered_set_refresh_rewrites_copied_edges_and_drops_old_targets() {
    let copy = address(0x1000);
    let promote = address(0x2000);
    let dead = address(0x3000);
    let copy_destination = address(0x9000);
    let promote_destination = address(0xa000);
    let first_source = address(0x4000);
    let promote_source = address(0x5000);
    let dead_source = address(0x6000);
    let second_source = address(0x7000);
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
    let mut remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(13));
    remembered_set
        .record(RememberedEdge::new(first_source, copy))
        .expect("copy edge records");
    remembered_set
        .record(RememberedEdge::new(promote_source, promote))
        .expect("promote edge records");
    remembered_set
        .record(RememberedEdge::new(dead_source, dead))
        .expect("dead edge records");
    remembered_set
        .record(RememberedEdge::new(second_source, copy))
        .expect("second copy edge records");

    let refresh_plan =
        MinorGcRememberedSetRefreshPlan::from_snapshot(remembered_set.snapshot(), &relocation_plan)
            .expect("refresh plan builds");

    assert_eq!(refresh_plan.source_epoch(), RememberedSetEpoch::new(13));
    assert_eq!(refresh_plan.len(), 4);
    assert!(!refresh_plan.is_empty());
    assert_eq!(
        refresh_plan.refreshes()[0].original(),
        RememberedEdge::new(first_source, copy)
    );
    assert_eq!(
        refresh_plan.refreshes()[0].action(),
        MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
            refreshed: RememberedEdge::new(first_source, copy_destination),
        }
    );
    assert_eq!(
        refresh_plan.refreshes()[0].retained_edge(),
        Some(RememberedEdge::new(first_source, copy_destination))
    );
    assert_eq!(
        refresh_plan.refreshes()[1].action(),
        MinorGcRememberedSetRefreshAction::DropPromoted {
            destination: promote_destination,
        }
    );
    assert_eq!(refresh_plan.refreshes()[1].retained_edge(), None);
    assert_eq!(
        refresh_plan.refreshes()[2].action(),
        MinorGcRememberedSetRefreshAction::DropDead
    );
    assert_eq!(refresh_plan.refreshes()[2].retained_edge(), None);
    assert_eq!(
        refresh_plan.refreshes()[3].action(),
        MinorGcRememberedSetRefreshAction::RetainCopiedYoung {
            refreshed: RememberedEdge::new(second_source, copy_destination),
        }
    );
    assert_eq!(
        refresh_plan.retained_edges().collect::<Vec<_>>(),
        [
            RememberedEdge::new(first_source, copy_destination),
            RememberedEdge::new(second_source, copy_destination),
        ]
    );
    let rebuilt = refresh_plan
        .rebuild_remembered_set()
        .expect("remembered set rebuilds");
    assert_eq!(rebuilt.epoch(), RememberedSetEpoch::new(14));
    assert_eq!(
        rebuilt.edges(),
        &[
            RememberedEdge::new(first_source, copy_destination),
            RememberedEdge::new(second_source, copy_destination),
        ]
    );
}

#[test]
fn minor_gc_remembered_set_refresh_accepts_empty_snapshots() {
    let relocation_plan = MinorGcRelocationPlan::default();
    let remembered_set = RememberedSet::with_epoch(RememberedSetEpoch::new(21));

    let refresh_plan =
        MinorGcRememberedSetRefreshPlan::from_snapshot(remembered_set.snapshot(), &relocation_plan)
            .expect("empty refresh plan builds");

    assert_eq!(refresh_plan.source_epoch(), RememberedSetEpoch::new(21));
    assert!(refresh_plan.is_empty());
    assert_eq!(refresh_plan.refreshes(), &[]);
    assert_eq!(refresh_plan.retained_edges().collect::<Vec<_>>(), []);
    let rebuilt = refresh_plan
        .rebuild_remembered_set()
        .expect("empty remembered set rebuilds");
    assert_eq!(rebuilt.epoch(), RememberedSetEpoch::new(22));
    assert_eq!(rebuilt.edges(), &[]);

    let max_epoch_set = RememberedSet::with_epoch(RememberedSetEpoch::new(u64::MAX));
    let max_epoch_refresh =
        MinorGcRememberedSetRefreshPlan::from_snapshot(max_epoch_set.snapshot(), &relocation_plan)
            .expect("max epoch empty refresh plan builds");
    assert_eq!(
        max_epoch_refresh.rebuild_remembered_set(),
        Err(GenerationalGcError::RememberedSetEpochOverflow)
    );
}
