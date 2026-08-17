//! Heap-field-writeback destination-binding tests, continued.

use super::*;

#[test]
fn empty_heap_field_writeback_write_plan_is_empty() {
    let writebacks = EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default();
    let live_bindings = EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default();

    let write_plan = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect("empty heap-field writeback write plan validates");

    assert!(write_plan.is_empty());
    assert_eq!(write_plan.report().fields(), 0);
    assert_eq!(write_plan.report().replacement_payload_bytes(), 0);
    assert_eq!(write_plan.report().writeback_object_payload_bytes(), 0);
}

#[test]
fn heap_field_writeback_applicator_routes_in_place_dirty_fields_to_direct_writer() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let replacement_request = request(
        source,
        replacement_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let write_plan = EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan::new(vec![
        EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite {
            allocation_domain: HeapAllocationDomain::Worker,
            validation_object: old_object,
            writeback_object: old_object,
            field_index: 0,
            source: field_source(),
            replacement_destination,
            replacement_generation: HeapGeneration::Old,
            replacement_metadata: heap(replacement_destination, HeapGeneration::Old),
            replacement_request,
            replacement_destination_bytes: vec![1, 2, 3, 4],
            writeback_object_request: None,
            writeback_object_destination_bytes: None,
        },
    ]);
    let mut heap = EvalHeap::new();
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();

    let err = apply_boundary_minor_gc_heap_field_writebacks(
        &mut heap,
        &mut remembered_set,
        &mut card_table,
        &write_plan,
    )
    .expect_err("direct in-place writeback is routed to the heap writer");

    assert!(matches!(
        err,
        EvalHeapError::UnknownCollectorPollReferenceSlotAddress {
            address: actual_address,
        } if actual_address == old_object
    ));
}

#[test]
fn rejects_missing_copied_heap_field_writeback_object_metadata() {
    let validation_object = address(0x1000);
    let replacement_source = address(0x2000);
    let writeback_object = address(0x3000);
    let replacement_destination = address(0x4000);
    let writebacks = writebacks(
        validation_object,
        writeback_object,
        heap(replacement_destination, HeapGeneration::Old),
    );
    let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
        HeapAllocationDomain::Worker,
        validation_object,
        writeback_object,
        0,
        field_source(),
        replacement_destination,
        HeapGeneration::Old,
        request(
            replacement_source,
            replacement_destination,
            MinorGcSurvivorAction::PromoteToOld,
        ),
        vec![1, 2, 3, 4],
        None,
        None,
    );
    let live_bindings = live_writeback_destination_bindings(vec![binding]);

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("missing copied writeback-object metadata is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectBindingMalformed {
            allocation_domain: HeapAllocationDomain::Worker,
            validation_object: actual_validation_object,
            writeback_object: actual_writeback_object,
            field_index: 0,
            field_source,
        } if actual_validation_object == validation_object
            && actual_writeback_object == writeback_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
    ));
}

#[test]
fn rejects_extra_old_field_writeback_object_metadata() {
    let old_object = address(0x1000);
    let replacement_source = address(0x2000);
    let replacement_destination = address(0x3000);
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
        HeapAllocationDomain::Worker,
        old_object,
        old_object,
        0,
        field_source(),
        replacement_destination,
        HeapGeneration::Young,
        request(
            replacement_source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3, 4],
        Some(request(
            old_object,
            old_object,
            MinorGcSurvivorAction::CopyToNursery,
        )),
        Some(vec![5, 6, 7, 8]),
    );
    let live_bindings = live_writeback_destination_bindings(vec![binding]);

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("extra old-field writeback-object metadata is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectBindingMalformed {
            allocation_domain: HeapAllocationDomain::Worker,
            validation_object,
            writeback_object,
            field_index: 0,
            field_source,
        } if validation_object == old_object
            && writeback_object == old_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
    ));
}

#[test]
fn rejects_copied_heap_field_writeback_object_request_from_another_source() {
    let validation_object = address(0x1000);
    let replacement_source = address(0x2000);
    let writeback_object = address(0x3000);
    let replacement_destination = address(0x4000);
    let wrong_source = address(0x5000);
    let writebacks = writebacks(
        validation_object,
        writeback_object,
        heap(replacement_destination, HeapGeneration::Old),
    );
    let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
        HeapAllocationDomain::Worker,
        validation_object,
        writeback_object,
        0,
        field_source(),
        replacement_destination,
        HeapGeneration::Old,
        request(
            replacement_source,
            replacement_destination,
            MinorGcSurvivorAction::PromoteToOld,
        ),
        vec![1, 2, 3, 4],
        Some(request(
            wrong_source,
            writeback_object,
            MinorGcSurvivorAction::CopyToNursery,
        )),
        Some(vec![5, 6, 7, 8]),
    );
    let live_bindings = live_writeback_destination_bindings(vec![binding]);

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("copied writeback-object request source mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestSourceMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            validation_object: actual_validation_object,
            writeback_object: actual_writeback_object,
            field_index: 0,
            field_source,
            actual_source,
        } if actual_validation_object == validation_object
            && actual_writeback_object == writeback_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && actual_source == wrong_source
    ));
}

#[test]
fn matches_copied_nursery_field_writeback_and_replacement_snapshots() {
    let validation_object = address(0x1000);
    let replacement_source = address(0x2000);
    let writeback_object = address(0x3000);
    let replacement_destination = address(0x4000);
    let writeback_request = request(
        validation_object,
        writeback_object,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let replacement_request = request(
        replacement_source,
        replacement_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let writeback_bytes = vec![1, 2, 3, 4];
    let replacement_bytes = vec![5, 6, 7, 8];
    let writebacks = writebacks(
        validation_object,
        writeback_object,
        heap(replacement_destination, HeapGeneration::Old),
    );
    let destination_storage = destination_storage(vec![
        (writeback_request, writeback_bytes.clone()),
        (replacement_request, replacement_bytes.clone()),
    ]);

    let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect("copied field binding report succeeds");

    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].validation_object(), validation_object);
    assert_eq!(bindings[0].writeback_object(), writeback_object);
    assert_eq!(
        bindings[0].replacement_destination(),
        replacement_destination
    );
    assert_eq!(bindings[0].replacement_generation(), HeapGeneration::Old);
    assert_eq!(bindings[0].replacement_request(), replacement_request);
    assert_eq!(
        bindings[0].replacement_destination_bytes(),
        replacement_bytes
    );
    assert_eq!(
        bindings[0].writeback_object_request(),
        Some(writeback_request)
    );
    assert_eq!(
        bindings[0].writeback_object_destination_bytes(),
        Some(writeback_bytes.as_slice())
    );
}

#[test]
fn rejects_heap_field_replacement_without_installed_destination_snapshot() {
    let old_object = address(0x1000);
    let replacement_destination = address(0x3000);
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

    let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect_err("missing replacement snapshot is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementMissing {
            writeback_object,
            field_index: 0,
            field_source: actual_field_source,
            replacement,
        } if writeback_object == old_object
            && actual_field_source == field_source()
            && replacement == replacement_destination
    ));
}

#[test]
fn rejects_copied_heap_field_without_writeback_object_snapshot() {
    let validation_object = address(0x1000);
    let replacement_source = address(0x2000);
    let writeback_object = address(0x3000);
    let replacement_destination = address(0x4000);
    let replacement_request = request(
        replacement_source,
        replacement_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let writebacks = writebacks(
        validation_object,
        writeback_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = destination_storage(vec![(replacement_request, vec![1, 2, 3, 4])]);

    let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect_err("missing copied writeback-object snapshot is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectMissing {
            validation_object: actual_validation_object,
            writeback_object: actual_writeback_object,
            field_index: 0,
            field_source: actual_field_source,
        } if actual_validation_object == validation_object
            && actual_writeback_object == writeback_object
            && actual_field_source == field_source()
    ));
}

#[test]
fn rejects_copied_heap_field_writeback_object_from_another_source() {
    let validation_object = address(0x1000);
    let replacement_source = address(0x2000);
    let writeback_object = address(0x3000);
    let replacement_destination = address(0x4000);
    let mismatched_source = address(0x5000);
    let replacement_request = request(
        replacement_source,
        replacement_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let mismatched_writeback_request = request(
        mismatched_source,
        writeback_object,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let writebacks = writebacks(
        validation_object,
        writeback_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = destination_storage(vec![
        (replacement_request, vec![1, 2, 3, 4]),
        (mismatched_writeback_request, vec![5, 6, 7, 8]),
    ]);

    let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect_err("writeback object from another source is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectSourceMismatch {
            validation_object: actual_validation_object,
            writeback_object: actual_writeback_object,
            field_index: 0,
            field_source: actual_field_source,
            actual_source,
        } if actual_validation_object == validation_object
            && actual_writeback_object == writeback_object
            && actual_field_source == field_source()
            && actual_source == mismatched_source
    ));
}

#[test]
fn rejects_non_heap_heap_field_replacement_metadata() {
    let old_object = address(0x1000);
    let writebacks = writebacks(old_object, old_object, ResolvedValueGeneration::Inline);
    let destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

    let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect_err("non-heap replacement metadata is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
            writeback_object,
            field_index: 0,
            field_source: actual_field_source,
            value: ResolvedValueGeneration::Inline,
        } if writeback_object == old_object && actual_field_source == field_source()
    ));
}

#[test]
fn rejects_destination_request_generation_that_disagrees_with_action() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let replacement_request = request_with_generation(
        source,
        replacement_destination,
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Old,
    );
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = destination_storage(vec![(replacement_request, vec![1, 2, 3, 4])]);

    let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect_err("destination request action/generation mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
            destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        } if destination == replacement_destination
    ));
}

#[test]
fn rejects_heap_field_replacement_generation_mismatch() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let replacement_request = request(
        source,
        replacement_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Old),
    );
    let destination_storage = destination_storage(vec![(replacement_request, vec![1, 2, 3, 4])]);

    let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect_err("replacement generation/action mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
            writeback_object,
            field_index: 0,
            field_source: actual_field_source,
            replacement,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        } if writeback_object == old_object
            && actual_field_source == field_source()
            && replacement == replacement_destination
    ));
}
