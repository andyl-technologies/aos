use super::*;
use crate::heap::gc::{
    MinorGcDestinationAllocationPlan, MinorGcDestinationPlacementPlan, MinorGcPromotionPolicy,
    MinorGcRelocationDestination, MinorGcRelocationPlan, NurseryObjectAge, NurseryObjectLayout,
    RememberedSet, RememberedSetEpoch, ResolvedValueGeneration,
};
use crate::value::tag::POINTER_TAG_MASK;

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("test address is aligned and non-null")
}

fn mixed_plan() -> (
    MinorGcPlan,
    Vec<NurseryObjectLayout>,
    MinorGcDestinationPlacementPlan,
) {
    let first_copy = address(0x1000);
    let promote = address(0x2000);
    let second_copy = address(0x3000);
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
    let layouts = vec![
        NurseryObjectLayout::new(second_copy, 3, 8),
        NurseryObjectLayout::new(promote, 6, 16),
        NurseryObjectLayout::new(first_copy, 4, 8),
    ];
    let allocation_plan = MinorGcDestinationAllocationPlan::from_minor_gc_plan(&plan, &layouts)
        .expect("allocation plan builds");
    let placement_plan = MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)
        .expect("placement plan builds");

    (plan, layouts, placement_plan)
}

fn copy_plan_for_storage(
    plan: &MinorGcPlan,
    layouts: &[NurseryObjectLayout],
    storage: &MinorGcOwnedDestinationStorage,
) -> MinorGcObjectCopyPlan {
    let destination_plan = storage
        .relocation_destination_plan(plan)
        .expect("storage materializes destinations");
    let relocation_plan = destination_plan
        .relocation_plan(plan)
        .expect("relocation plan builds");
    MinorGcObjectCopyPlan::from_relocation_plan(&relocation_plan, layouts)
        .expect("object-copy plan builds")
}

fn copy_plan_from_destinations(
    plan: &MinorGcPlan,
    destinations: &[MinorGcRelocationDestination],
    layouts: &[NurseryObjectLayout],
) -> MinorGcObjectCopyPlan {
    let relocation_plan = MinorGcRelocationPlan::from_minor_gc_plan(plan, destinations)
        .expect("relocation plan builds");
    MinorGcObjectCopyPlan::from_relocation_plan(&relocation_plan, layouts)
        .expect("object-copy plan builds")
}

#[test]
fn minor_gc_owned_destination_storage_materializes_bases_and_copies_sources() {
    let (plan, layouts, placement_plan) = mixed_plan();
    let mut storage = MinorGcOwnedDestinationStorage::from_placement_plan(&placement_plan)
        .expect("owned destination storage allocates");
    let bases = storage.destination_bases();
    let copy_plan = copy_plan_for_storage(&plan, &layouts, &storage);
    let first_copy_source = [1, 2, 3, 4];
    let promote_source = [5, 6, 7, 8, 9, 10];
    let second_copy_source = [11, 12, 13];
    let planned_report =
        MinorGcOwnedDestinationStorageCopyReport::from_object_copy_plan(&copy_plan);

    assert_eq!(planned_report.object_copies(), 3);
    assert_eq!(planned_report.copied_to_nursery(), 2);
    assert_eq!(planned_report.promoted_to_old(), 1);
    assert_eq!(planned_report.nursery_payload_bytes(), 7);
    assert_eq!(planned_report.old_payload_bytes(), 6);

    let report = storage
        .copy_from_sources(
            &copy_plan,
            &[
                MinorGcSourceObjectBytes::new(address(0x1000), &first_copy_source),
                MinorGcSourceObjectBytes::new(address(0x2000), &promote_source),
                MinorGcSourceObjectBytes::new(address(0x3000), &second_copy_source),
            ],
        )
        .expect("source bytes copy into owned storage");

    assert_eq!(storage.placement_plan(), &placement_plan);
    assert_eq!(storage.nursery_reserved_bytes(), 11);
    assert_eq!(storage.old_reserved_bytes(), 6);
    assert_eq!(report, planned_report);
    assert_eq!(
        storage.generation_destination_bytes(HeapGeneration::Permanent),
        None
    );
    assert_eq!(bases.nursery().address_bits() & POINTER_TAG_MASK, 0);
    assert_eq!(bases.old().address_bits() & POINTER_TAG_MASK, 0);
    for copy in copy_plan.copies() {
        assert_eq!(copy.destination().address_bits() & (copy.align() - 1), 0);
    }
    assert_eq!(report.object_copies(), 3);
    assert_eq!(report.copied_to_nursery(), 2);
    assert_eq!(report.promoted_to_old(), 1);
    assert_eq!(report.nursery_payload_bytes(), 7);
    assert_eq!(report.old_payload_bytes(), 6);
    assert_eq!(
        &storage.nursery_destination_bytes()[0..4],
        first_copy_source
    );
    assert_eq!(&storage.nursery_destination_bytes()[4..8], [0, 0, 0, 0]);
    assert_eq!(
        &storage.nursery_destination_bytes()[8..11],
        second_copy_source
    );
    assert_eq!(storage.old_destination_bytes(), promote_source);
    assert_eq!(
        storage.generation_destination_bytes(HeapGeneration::Young),
        Some(storage.nursery_destination_bytes())
    );
    assert_eq!(
        storage.generation_destination_bytes(HeapGeneration::Old),
        Some(storage.old_destination_bytes())
    );
}

#[test]
fn minor_gc_owned_destination_storage_accepts_empty_placement_plan() {
    let mut storage = MinorGcOwnedDestinationStorage::from_placement_plan(
        &MinorGcDestinationPlacementPlan::default(),
    )
    .expect("empty storage still has aligned bases");
    let report = storage
        .copy_from_sources(&MinorGcObjectCopyPlan::default(), &[])
        .expect("empty copy plan copies no bytes");

    assert_eq!(storage.nursery_reserved_bytes(), 0);
    assert_eq!(storage.old_reserved_bytes(), 0);
    assert!(storage.nursery_destination_bytes().is_empty());
    assert!(storage.old_destination_bytes().is_empty());
    assert_eq!(
        storage.destination_bases().nursery().address_bits() & POINTER_TAG_MASK,
        0
    );
    assert_eq!(
        storage.destination_bases().old().address_bits() & POINTER_TAG_MASK,
        0
    );
    assert_eq!(report, MinorGcOwnedDestinationStorageCopyReport::default());
}

#[test]
fn minor_gc_owned_destination_storage_rejects_source_inventory_mismatches() {
    let (plan, layouts, placement_plan) = mixed_plan();
    let mut storage = MinorGcOwnedDestinationStorage::from_placement_plan(&placement_plan)
        .expect("owned destination storage allocates");
    let copy_plan = copy_plan_for_storage(&plan, &layouts, &storage);
    let first_copy_source = [1, 2, 3, 4];
    let short_promote_source = [5, 6, 7, 8, 9];
    let second_copy_source = [11, 12, 13];

    assert_eq!(
        storage.copy_from_sources(
            &copy_plan,
            &[MinorGcSourceObjectBytes::new(
                address(0x1000),
                &first_copy_source
            )],
        ),
        Err(GenerationalGcError::MinorGcSourceObjectBytesCountMismatch {
            copies: 3,
            sources: 1,
        })
    );
    assert_eq!(
        storage.copy_from_sources(
            &copy_plan,
            &[
                MinorGcSourceObjectBytes::new(address(0x1000), &first_copy_source),
                MinorGcSourceObjectBytes::new(address(0x3000), &second_copy_source),
                MinorGcSourceObjectBytes::new(address(0x2000), &short_promote_source),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcSourceObjectBytesSourceMismatch {
                index: 1,
                expected: address(0x2000),
                actual: address(0x3000),
            }
        )
    );
    assert_eq!(
        storage.copy_from_sources(
            &copy_plan,
            &[
                MinorGcSourceObjectBytes::new(address(0x1000), &first_copy_source),
                MinorGcSourceObjectBytes::new(address(0x2000), &short_promote_source),
                MinorGcSourceObjectBytes::new(address(0x3000), &second_copy_source),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcSourceObjectBytesLengthMismatch {
                index: 1,
                address: address(0x2000),
                expected: 6,
                actual: 5,
            }
        )
    );
    assert_eq!(storage.nursery_destination_bytes(), [0; 11]);
    assert_eq!(storage.old_destination_bytes(), [0; 6]);
}

#[test]
fn minor_gc_owned_destination_storage_rejects_copy_plan_mismatches() {
    let (plan, layouts, placement_plan) = mixed_plan();
    let first_copy = address(0x1000);
    let promote = address(0x2000);
    let second_copy = address(0x3000);
    let mut storage = MinorGcOwnedDestinationStorage::from_placement_plan(&placement_plan)
        .expect("owned destination storage allocates");
    let first_copy_source = [1, 2, 3, 4];
    let promote_source = [5, 6, 7, 8, 9, 10];
    let second_copy_source = [11, 12, 13];

    let short_plan = MinorGcPlan::from_roots_and_remembered(
        [ResolvedValueGeneration::young(first_copy)],
        RememberedSet::new().snapshot(),
        RememberedSetEpoch::new(0),
        &[NurseryObjectAge::new(first_copy, 0)],
        MinorGcPromotionPolicy::new(2),
    )
    .expect("short minor GC plan builds");
    let short_copy_plan = copy_plan_from_destinations(
        &short_plan,
        &[MinorGcRelocationDestination::new(
            first_copy,
            storage.destination_bases().nursery(),
        )],
        &[NurseryObjectLayout::new(first_copy, 4, 8)],
    );

    assert_eq!(
        storage.copy_from_sources(
            &short_copy_plan,
            &[MinorGcSourceObjectBytes::new(
                first_copy,
                &first_copy_source
            )],
        ),
        Err(
            GenerationalGcError::MinorGcDestinationStorageCopyPlanLengthMismatch {
                placements: 3,
                copies: 1,
            }
        )
    );

    let expected_second_copy = address(storage.destination_bases().nursery().address_bits() + 8);
    let wrong_second_copy = address(storage.destination_bases().nursery().address_bits() + 16);
    let wrong_destination_copy_plan = copy_plan_from_destinations(
        &plan,
        &[
            MinorGcRelocationDestination::new(first_copy, storage.destination_bases().nursery()),
            MinorGcRelocationDestination::new(promote, storage.destination_bases().old()),
            MinorGcRelocationDestination::new(second_copy, wrong_second_copy),
        ],
        &layouts,
    );

    assert_eq!(
        storage.copy_from_sources(
            &wrong_destination_copy_plan,
            &[
                MinorGcSourceObjectBytes::new(first_copy, &first_copy_source),
                MinorGcSourceObjectBytes::new(promote, &promote_source),
                MinorGcSourceObjectBytes::new(second_copy, &second_copy_source),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcDestinationStorageCopyDestinationMismatch {
                address: second_copy,
                expected: expected_second_copy,
                actual: wrong_second_copy,
            }
        )
    );

    let wrong_size_layouts = [
        NurseryObjectLayout::new(second_copy, 4, 8),
        NurseryObjectLayout::new(promote, 6, 16),
        NurseryObjectLayout::new(first_copy, 4, 8),
    ];
    let wrong_size_copy_plan = copy_plan_for_storage(&plan, &wrong_size_layouts, &storage);
    let wrong_size_second_source = [11, 12, 13, 14];

    assert_eq!(
        storage.copy_from_sources(
            &wrong_size_copy_plan,
            &[
                MinorGcSourceObjectBytes::new(first_copy, &first_copy_source),
                MinorGcSourceObjectBytes::new(promote, &promote_source),
                MinorGcSourceObjectBytes::new(second_copy, &wrong_size_second_source),
            ],
        ),
        Err(
            GenerationalGcError::MinorGcDestinationStorageCopySizeMismatch {
                address: second_copy,
                expected: 3,
                actual: 4,
            }
        )
    );
    assert_eq!(storage.nursery_destination_bytes(), [0; 11]);
    assert_eq!(storage.old_destination_bytes(), [0; 6]);
}
