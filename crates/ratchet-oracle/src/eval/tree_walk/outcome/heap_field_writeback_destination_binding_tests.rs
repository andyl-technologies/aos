//! Tests for heap-field-writeback destination-binding derivation.

use super::*;

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("test address is non-zero")
}

fn field_source() -> HeapEdgeSource {
    HeapEdgeSource::ListElement { index: 0 }
}

fn heap(address: GcHeapAddress, generation: HeapGeneration) -> ResolvedValueGeneration {
    ResolvedValueGeneration::Heap {
        address,
        generation,
    }
}

fn request(
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
) -> AllocationCollectorPollObjectByteCopyRequest {
    request_with_generation(
        source,
        destination,
        action,
        generation_for_destination_action(action),
    )
}

fn request_with_generation(
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    destination_generation: HeapGeneration,
) -> AllocationCollectorPollObjectByteCopyRequest {
    AllocationCollectorPollObjectByteCopyRequest::for_test(
        source,
        destination,
        action,
        destination_generation,
        4,
        8,
    )
}

fn writebacks(
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    replacement: ResolvedValueGeneration,
) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
    let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
        AllocationCollectorPollReferenceWritebackReport::default(),
        Vec::new(),
        Vec::new(),
        vec![AllocationCollectorPollHeapFieldWritebackSlot::new(
            validation_object,
            writeback_object,
            0,
            field_source(),
            replacement,
        )],
    );
    let applications =
        EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(Some(application), None);
    let install_report = live_reference_writeback_install_report(&applications);
    EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        install_report,
        applications,
    }
}

fn duplicated_writebacks(
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    replacement: ResolvedValueGeneration,
) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
    let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
        AllocationCollectorPollReferenceWritebackReport::default(),
        Vec::new(),
        Vec::new(),
        vec![
            AllocationCollectorPollHeapFieldWritebackSlot::new(
                validation_object,
                writeback_object,
                0,
                field_source(),
                replacement,
            ),
            AllocationCollectorPollHeapFieldWritebackSlot::new(
                validation_object,
                writeback_object,
                0,
                field_source(),
                replacement,
            ),
        ],
    );
    let applications =
        EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(Some(application), None);
    let install_report = live_reference_writeback_install_report(&applications);
    EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        install_report,
        applications,
    }
}

fn destination_storage(
    objects: Vec<(AllocationCollectorPollObjectByteCopyRequest, Vec<u8>)>,
) -> EvalGcStressBoundaryMinorGcLiveDestinationStorage {
    let object_bytes = objects
        .into_iter()
        .map(|(request, destination_bytes)| {
            EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(request, destination_bytes)
        })
        .collect::<Vec<_>>();
    let install_report = live_destination_storage_install_report(&object_bytes);
    EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        install_report,
        object_bytes,
    }
}

fn live_writeback_destination_bindings(
    heap_field_writeback_bindings: Vec<
        EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
    >,
) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
    let install_report =
        live_writeback_destination_binding_install_report(&[], &heap_field_writeback_bindings);
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
        install_report,
        root_writeback_bindings: Vec::new(),
        heap_field_writeback_bindings,
        expected_remembered_set: None,
    }
}

mod part_1;

#[test]
fn matches_dirty_old_field_replacement_destination_snapshot() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let replacement_request = request(
        source,
        replacement_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let colliding_writeback_object_request = request(
        address(0x4000),
        old_object,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let replacement_bytes = vec![1, 2, 3, 4];
    let colliding_writeback_bytes = vec![5, 6, 7, 8];
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = destination_storage(vec![
        (
            colliding_writeback_object_request,
            colliding_writeback_bytes,
        ),
        (replacement_request, replacement_bytes.clone()),
    ]);

    let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect("dirty old-field binding report succeeds");

    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(bindings[0].validation_object(), old_object);
    assert_eq!(bindings[0].writeback_object(), old_object);
    assert_eq!(bindings[0].field_index(), 0);
    assert_eq!(bindings[0].source(), &field_source());
    assert_eq!(
        bindings[0].replacement_destination(),
        replacement_destination
    );
    assert_eq!(bindings[0].replacement_generation(), HeapGeneration::Young);
    assert_eq!(bindings[0].replacement_request(), replacement_request);
    assert_eq!(
        bindings[0].replacement_destination_bytes(),
        replacement_bytes
    );
    assert_eq!(bindings[0].writeback_object_request(), None);
    assert_eq!(bindings[0].writeback_object_destination_bytes(), None);
}

#[test]
fn plans_heap_field_writeback_writes_from_live_bindings() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let replacement_request = request(
        source,
        replacement_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let replacement_bytes = vec![1, 2, 3, 4];
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage =
        destination_storage(vec![(replacement_request, replacement_bytes.clone())]);
    let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect("heap-field binding report succeeds");
    let live_bindings = live_writeback_destination_bindings(bindings);

    let write_plan = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect("heap-field writeback write plan validates");

    assert_eq!(write_plan.len(), 1);
    assert_eq!(write_plan.report().fields(), 1);
    assert_eq!(write_plan.report().copied_replacements_to_nursery(), 1);
    assert_eq!(write_plan.report().promoted_replacements_to_old(), 0);
    assert_eq!(
        write_plan.report().replacement_payload_bytes(),
        replacement_bytes.len()
    );
    assert_eq!(write_plan.report().writeback_object_payload_bytes(), 0);
    assert_eq!(
        write_plan.writes()[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(write_plan.writes()[0].validation_object(), old_object);
    assert_eq!(write_plan.writes()[0].writeback_object(), old_object);
    assert_eq!(write_plan.writes()[0].field_index(), 0);
    assert_eq!(write_plan.writes()[0].source(), &field_source());
    assert_eq!(
        write_plan.writes()[0].replacement_destination(),
        replacement_destination
    );
    assert_eq!(
        write_plan.writes()[0].replacement_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        write_plan.writes()[0].replacement_metadata(),
        heap(replacement_destination, HeapGeneration::Young)
    );
    assert_eq!(
        write_plan.writes()[0].replacement_request(),
        replacement_request
    );
    assert_eq!(
        write_plan.writes()[0].replacement_destination_bytes(),
        replacement_bytes
    );
    assert_eq!(write_plan.writes()[0].writeback_object_request(), None);
    assert_eq!(
        write_plan.writes()[0].writeback_object_destination_bytes(),
        None
    );
}

#[test]
fn rejects_heap_field_writeback_write_without_installed_binding() {
    let old_object = address(0x1000);
    let replacement_destination = address(0x3000);
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let live_bindings = EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default();

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("missing heap-field binding is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteMissingBinding {
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object,
            field_index: 0,
            field_source,
            replacement,
            generation: HeapGeneration::Young,
        } if writeback_object == old_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && replacement == replacement_destination
    ));
}

#[test]
fn rejects_heap_field_writeback_write_stale_binding() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let stale_replacement_destination = address(0x4000);
    let current_writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let stale_writebacks = writebacks(
        old_object,
        old_object,
        heap(stale_replacement_destination, HeapGeneration::Young),
    );
    let stale_storage = destination_storage(vec![(
        request(
            source,
            stale_replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3, 4],
    )]);
    let stale_bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &stale_writebacks,
        &stale_storage,
    )
    .expect("stale heap-field binding report succeeds");
    let live_bindings = live_writeback_destination_bindings(stale_bindings);

    let err =
        boundary_minor_gc_heap_field_writeback_write_plan(&current_writebacks, &live_bindings)
            .expect_err("stale heap-field binding is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteBindingMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object,
            field_index: 0,
            field_source,
            expected_replacement,
            expected_generation: HeapGeneration::Young,
            actual_replacement,
            actual_generation: HeapGeneration::Young,
        } if writeback_object == old_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && expected_replacement == replacement_destination
            && actual_replacement == stale_replacement_destination
    ));
}

#[test]
fn rejects_duplicate_heap_field_writeback_write_sources() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let writebacks = duplicated_writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = destination_storage(vec![(
        request(
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3, 4],
    )]);
    let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect("duplicate heap-field binding report currently mirrors the slots");
    let live_bindings = live_writeback_destination_bindings(bindings);

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("duplicate heap-field writeback sources are rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
            index: 1,
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object,
            field_index: 0,
            field_source,
        } if writeback_object == old_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
    ));
}

#[test]
fn rejects_duplicate_heap_field_writeback_write_bindings() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = destination_storage(vec![(
        request(
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3, 4],
    )]);
    let binding = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect("heap-field binding report succeeds")[0]
        .clone();
    let live_bindings = live_writeback_destination_bindings(vec![binding.clone(), binding]);

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("duplicate heap-field destination bindings are rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateBinding {
            index: 1,
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object,
            field_index: 0,
            field_source,
        } if writeback_object == old_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
    ));
}

#[test]
fn rejects_unbound_heap_field_writeback_binding() {
    let old_object = address(0x1000);
    let source = address(0x2000);
    let replacement_destination = address(0x3000);
    let writebacks = writebacks(
        old_object,
        old_object,
        heap(replacement_destination, HeapGeneration::Young),
    );
    let destination_storage = destination_storage(vec![(
        request(
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3, 4],
    )]);
    let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
        &writebacks,
        &destination_storage,
    )
    .expect("heap-field binding report succeeds");
    let live_bindings = live_writeback_destination_bindings(bindings);
    let empty_writebacks = EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default();

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&empty_writebacks, &live_bindings)
        .expect_err("unbound heap-field binding is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteUnboundBinding {
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object,
            field_index: 0,
            field_source,
            replacement,
            generation: HeapGeneration::Young,
        } if writeback_object == old_object
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && replacement == replacement_destination
    ));
}

#[test]
fn rejects_heap_field_binding_replacement_payload_size_mismatch() {
    let old_object = address(0x1000);
    let source = address(0x2000);
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
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3],
        None,
        None,
    );
    let live_bindings = live_writeback_destination_bindings(vec![binding]);

    let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("binding replacement payload length mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
            destination,
            expected: 4,
            actual: 3,
        } if destination == replacement_destination
    ));
}

#[test]
fn plans_copied_nursery_heap_field_writeback_writes_from_live_bindings() {
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
    .expect("copied heap-field binding report succeeds");
    let live_bindings = live_writeback_destination_bindings(bindings);

    let write_plan = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
        .expect("copied heap-field writeback write plan validates");

    assert_eq!(write_plan.len(), 1);
    assert_eq!(write_plan.report().fields(), 1);
    assert_eq!(write_plan.report().copied_replacements_to_nursery(), 0);
    assert_eq!(write_plan.report().promoted_replacements_to_old(), 1);
    assert_eq!(
        write_plan.report().replacement_payload_bytes(),
        replacement_bytes.len()
    );
    assert_eq!(
        write_plan.report().writeback_object_payload_bytes(),
        writeback_bytes.len()
    );
    assert_eq!(
        write_plan.writes()[0].validation_object(),
        validation_object
    );
    assert_eq!(write_plan.writes()[0].writeback_object(), writeback_object);
    assert_eq!(
        write_plan.writes()[0].replacement_destination(),
        replacement_destination
    );
    assert_eq!(
        write_plan.writes()[0].replacement_generation(),
        HeapGeneration::Old
    );
    assert_eq!(
        write_plan.writes()[0].replacement_request(),
        replacement_request
    );
    assert_eq!(
        write_plan.writes()[0].replacement_destination_bytes(),
        replacement_bytes
    );
    assert_eq!(
        write_plan.writes()[0].writeback_object_request(),
        Some(writeback_request)
    );
    assert_eq!(
        write_plan.writes()[0].writeback_object_destination_bytes(),
        Some(writeback_bytes.as_slice())
    );
}
