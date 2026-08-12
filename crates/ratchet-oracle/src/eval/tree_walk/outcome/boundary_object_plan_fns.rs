//! Object byte-copy, destination-storage, object-generation, and forwarding plan/apply helpers.

use super::*;

pub(crate) fn boundary_minor_gc_object_byte_copy_applications(
    plan: &AllocationCollectorPollObjectByteCopyPlan,
) -> Result<Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>, EvalHeapError> {
    let requests = plan.requests();
    let mut applications = Vec::new();
    applications
        .try_reserve_exact(requests.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_APPLICATIONS_TABLE,
            entries: requests.len(),
        })?;

    for (index, request) in requests.iter().copied().enumerate() {
        applications.push(EvalGcStressBoundaryMinorGcObjectByteCopyApplication::new(
            request,
            boundary_minor_gc_object_source_bytes(index, request.size_bytes())?,
            boundary_minor_gc_object_destination_bytes(request.size_bytes())?,
        ));
    }

    Ok(applications)
}

pub(crate) fn boundary_minor_gc_object_source_byte_storage(
    plan: &AllocationCollectorPollObjectByteCopyPlan,
) -> Result<Vec<Vec<u8>>, EvalHeapError> {
    let requests = plan.requests();
    let mut sources = Vec::new();
    sources.try_reserve_exact(requests.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE,
            entries: requests.len(),
        }
    })?;
    for (index, request) in requests.iter().copied().enumerate() {
        sources.push(boundary_minor_gc_object_source_bytes(
            index,
            request.size_bytes(),
        )?);
    }
    Ok(sources)
}

pub(crate) fn boundary_minor_gc_object_source_bytes(
    index: usize,
    size_bytes: usize,
) -> Result<Vec<u8>, EvalHeapError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size_bytes)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE,
            entries: size_bytes,
        })?;
    let seed = index.to_le_bytes()[0].wrapping_mul(31).wrapping_add(0xa5);
    for offset in 0..size_bytes {
        bytes.push(seed.wrapping_add(offset.to_le_bytes()[0]));
    }
    Ok(bytes)
}

pub(crate) fn boundary_minor_gc_object_destination_bytes(
    size_bytes: usize,
) -> Result<Vec<u8>, EvalHeapError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size_bytes)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_DESTINATION_BYTES_TABLE,
            entries: size_bytes,
        })?;
    bytes.resize(size_bytes, 0);
    Ok(bytes)
}

pub(crate) fn boundary_minor_gc_object_byte_copy_buffers<'a>(
    applications: &'a mut [EvalGcStressBoundaryMinorGcObjectByteCopyApplication],
) -> Result<Vec<MinorGcObjectByteCopyBuffer<'a>>, EvalHeapError> {
    let mut buffers = Vec::new();
    buffers.try_reserve_exact(applications.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_BUFFERS_TABLE,
            entries: applications.len(),
        }
    })?;

    for application in applications.iter_mut() {
        let request = application.request;
        let source_bytes = application.source_bytes.as_slice();
        let destination_bytes = application.destination_bytes.as_mut_slice();
        buffers.push(MinorGcObjectByteCopyBuffer::new(
            request.source(),
            request.destination(),
            source_bytes,
            destination_bytes,
        ));
    }

    Ok(buffers)
}

pub(crate) fn boundary_minor_gc_destination_storage_application_from_storage(
    copy_report: MinorGcOwnedDestinationStorageCopyReport,
    storage: &MinorGcOwnedDestinationStorage,
) -> Result<EvalGcStressBoundaryMinorGcDestinationStorageApplication, EvalHeapError> {
    let nursery_reserved_bytes = storage.nursery_reserved_bytes();
    let old_reserved_bytes = storage.old_reserved_bytes();
    let nursery_destination_bytes = clone_boundary_destination_storage_bytes(
        BOUNDARY_MINOR_GC_NURSERY_DESTINATION_STORAGE_BYTES_TABLE,
        storage.nursery_destination_bytes(),
    )?;
    let old_destination_bytes = clone_boundary_destination_storage_bytes(
        BOUNDARY_MINOR_GC_OLD_DESTINATION_STORAGE_BYTES_TABLE,
        storage.old_destination_bytes(),
    )?;

    Ok(
        EvalGcStressBoundaryMinorGcDestinationStorageApplication::new(
            copy_report,
            nursery_reserved_bytes,
            old_reserved_bytes,
            nursery_destination_bytes,
            old_destination_bytes,
        ),
    )
}

pub(crate) fn boundary_minor_gc_destination_storage_application(
    relocation_plan: &EvalGcStressBoundaryMinorGcRelocationPlan,
    object_byte_copies: &[EvalGcStressBoundaryMinorGcObjectByteCopyApplication],
) -> Result<EvalGcStressBoundaryMinorGcDestinationStorageApplication, EvalHeapError> {
    let placement_plan = relocation_plan.relocation_destinations().placement_plan();
    let mut storage = MinorGcOwnedDestinationStorage::from_placement_plan(placement_plan)?;
    let copy_plan = boundary_minor_gc_destination_storage_copy_plan(
        &storage,
        relocation_plan.minor_gc_plan().plan(),
        placement_plan,
    )?;
    let source_bytes = boundary_minor_gc_source_object_bytes(object_byte_copies)?;
    let copy_report = storage.copy_from_sources(&copy_plan, &source_bytes)?;
    boundary_minor_gc_destination_storage_application_from_storage(copy_report, &storage)
}

pub(crate) fn boundary_minor_gc_destination_storage_copy_plan(
    storage: &MinorGcOwnedDestinationStorage,
    plan: &MinorGcPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<MinorGcObjectCopyPlan, EvalHeapError> {
    let destination_plan = storage.relocation_destination_plan(plan)?;
    let relocation_plan = destination_plan.relocation_plan(plan)?;
    let nursery_layouts = boundary_minor_gc_nursery_layouts_from_placements(placement_plan)?;
    Ok(MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &nursery_layouts,
    )?)
}

pub(crate) fn boundary_minor_gc_nursery_layouts_from_placements(
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<Vec<NurseryObjectLayout>, EvalHeapError> {
    let mut nursery_layouts = Vec::new();
    nursery_layouts
        .try_reserve_exact(placement_plan.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_DESTINATION_STORAGE_LAYOUTS_TABLE,
            entries: placement_plan.len(),
        })?;
    for placement in placement_plan.placements() {
        nursery_layouts.push(NurseryObjectLayout::new(
            placement.source(),
            placement.size_bytes(),
            placement.align(),
        ));
    }
    Ok(nursery_layouts)
}

pub(crate) fn boundary_minor_gc_source_object_bytes<'a>(
    applications: &'a [EvalGcStressBoundaryMinorGcObjectByteCopyApplication],
) -> Result<Vec<MinorGcSourceObjectBytes<'a>>, EvalHeapError> {
    let mut sources = Vec::new();
    sources.try_reserve_exact(applications.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_SOURCE_OBJECT_BYTES_TABLE,
            entries: applications.len(),
        }
    })?;
    for application in applications {
        sources.push(MinorGcSourceObjectBytes::new(
            application.request().source(),
            application.source_bytes(),
        ));
    }
    Ok(sources)
}

pub(crate) fn boundary_minor_gc_source_object_bytes_from_storage<'a>(
    plan: &AllocationCollectorPollObjectByteCopyPlan,
    source_byte_storage: &'a [Vec<u8>],
) -> Result<Vec<MinorGcSourceObjectBytes<'a>>, EvalHeapError> {
    let requests = plan.requests();
    if source_byte_storage.len() != requests.len() {
        return Err(GenerationalGcError::MinorGcSourceObjectBytesCountMismatch {
            copies: requests.len(),
            sources: source_byte_storage.len(),
        }
        .into());
    }
    let mut sources = Vec::new();
    sources.try_reserve_exact(requests.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_SOURCE_OBJECT_BYTES_TABLE,
            entries: requests.len(),
        }
    })?;
    for (request, source_bytes) in requests.iter().copied().zip(source_byte_storage) {
        sources.push(MinorGcSourceObjectBytes::new(
            request.source(),
            source_bytes.as_slice(),
        ));
    }
    Ok(sources)
}

pub(crate) fn clone_boundary_destination_storage_bytes(
    table: &'static str,
    bytes: &[u8],
) -> Result<Vec<u8>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(bytes.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table,
            entries: bytes.len(),
        })?;
    cloned.extend_from_slice(bytes);
    Ok(cloned)
}

pub(crate) fn live_destination_storage_install_report(
    object_bytes: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
    let mut report = EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport::default();
    for object in object_bytes {
        report.record(object.request());
    }
    report
}

pub(crate) fn live_object_generation_install_report(
    object_generations: &[EvalGcStressBoundaryMinorGcLiveObjectGeneration],
) -> EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
    let mut report = EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport::default();
    for generation in object_generations {
        report.record(generation);
    }
    report
}

pub(crate) fn live_forwarding_destination_binding_install_report(
    forwarding_destination_bindings: &[EvalGcStressBoundaryMinorGcForwardingDestinationBinding],
) -> EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport::new(
        forwarding_destination_bindings.len(),
    )
}

pub(crate) fn live_reference_writeback_install_report(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport {
    let mut report = EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport::default();
    if let Some(application) = applications.worker() {
        report.record(application);
    }
    if let Some(application) = applications.permanent_shared() {
        report.record(application);
    }
    report
}

pub(crate) fn live_writeback_destination_binding_install_report(
    root_writeback_bindings: &[EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding],
    heap_field_writeback_bindings: &[EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding],
) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport::new(
        root_writeback_bindings.len(),
        heap_field_writeback_bindings.len(),
    )
}

pub(crate) fn boundary_minor_gc_destination_object_generation_bindings(
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding>, EvalHeapError> {
    boundary_minor_gc_destination_object_generation_bindings_from_objects(
        destination_storage.object_bytes(),
    )
}

pub(crate) fn boundary_minor_gc_live_object_generations_from_objects(
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>, EvalHeapError> {
    validate_boundary_minor_gc_destination_generation_objects(destination_objects)?;
    let mut object_generations = Vec::new();
    object_generations
        .try_reserve_exact(destination_objects.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_OBJECT_GENERATIONS_TABLE,
            entries: destination_objects.len(),
        })?;

    for object in destination_objects {
        let generation = validated_destination_object_generation(object)?;
        object_generations.push(EvalGcStressBoundaryMinorGcLiveObjectGeneration::new(
            object.source(),
            object.destination(),
            object.request().action(),
            generation,
            object.request(),
        ));
    }

    Ok(object_generations)
}

pub(crate) fn boundary_minor_gc_object_body_generation_preflight_plan_from_generations(
    object_generations: &[EvalGcStressBoundaryMinorGcLiveObjectGeneration],
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(object_generations.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BODY_GENERATION_PREFLIGHT_REQUESTS_TABLE,
            entries: object_generations.len(),
        })?;

    for generation in object_generations {
        requests.push(generation.request());
    }

    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

pub(crate) fn boundary_minor_gc_destination_object_generation_bindings_from_objects(
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding>, EvalHeapError> {
    validate_boundary_minor_gc_destination_generation_objects(destination_objects)?;
    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(destination_objects.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_DESTINATION_OBJECT_GENERATION_BINDINGS_TABLE,
            entries: destination_objects.len(),
        })?;

    for object in destination_objects {
        let generation = validated_destination_object_generation(object)?;
        bindings.push(
            EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding::new(
                object.source(),
                object.destination(),
                object.request().action(),
                generation,
                object.request(),
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_DESTINATION_OBJECT_GENERATION_BINDINGS_TABLE,
                    object.destination_bytes(),
                )?,
            ),
        );
    }

    Ok(bindings)
}

pub(crate) fn boundary_minor_gc_object_generation_write_plan(
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
    live_object_generations: &EvalGcStressBoundaryMinorGcLiveObjectGenerations,
) -> Result<EvalGcStressBoundaryMinorGcObjectGenerationWritePlan, EvalHeapError> {
    let bindings = boundary_minor_gc_destination_object_generation_bindings(destination_storage)?;
    let generations = live_object_generations.object_generations();
    validate_boundary_minor_gc_object_generation_write_generations(generations)?;
    validate_boundary_minor_gc_object_generation_write_bindings(&bindings)?;

    let mut writes = Vec::new();
    writes.try_reserve_exact(generations.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
            entries: generations.len(),
        }
    })?;

    for generation in generations {
        let Some(binding) = bindings
            .iter()
            .find(|binding| binding.source() == generation.source())
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteMissingDestination {
                    source_address: generation.source(),
                    destination: generation.destination(),
                    action: generation.action(),
                    generation: generation.generation(),
                },
            );
        };

        if !object_generation_write_generation_matches_binding(generation, binding) {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteBindingMismatch {
                    source_address: generation.source(),
                    expected: generation.request(),
                    expected_generation: generation.generation(),
                    actual: binding.request(),
                    actual_generation: binding.generation(),
                },
            );
        }

        writes.push(
            EvalGcStressBoundaryMinorGcObjectGenerationWrite::from_generation_and_binding(
                generation, binding,
            )?,
        );
    }

    for binding in &bindings {
        if !writes
            .iter()
            .any(|write| object_generation_write_matches_binding(write, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteUnboundDestination {
                    source_address: binding.source(),
                    destination: binding.destination(),
                    action: binding.action(),
                    generation: binding.generation(),
                },
            );
        }
    }

    Ok(EvalGcStressBoundaryMinorGcObjectGenerationWritePlan::new(
        writes,
    ))
}

pub(crate) fn validate_boundary_minor_gc_object_generation_write_generations(
    generations: &[EvalGcStressBoundaryMinorGcLiveObjectGeneration],
) -> Result<(), EvalHeapError> {
    for (index, generation) in generations.iter().enumerate() {
        if generations[..index]
            .iter()
            .any(|existing| existing.source() == generation.source())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateSource {
                    index,
                    source_address: generation.source(),
                },
            );
        }
        if let Some(existing) = generations[..index]
            .iter()
            .find(|existing| existing.destination() == generation.destination())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestination {
                    index,
                    source_address: generation.source(),
                    existing_source_address: existing.source(),
                    destination: generation.destination(),
                },
            );
        }

        let request = generation.request();
        if request.source() != generation.source() {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestSourceMismatch {
                    source_address: generation.source(),
                    request_source: request.source(),
                },
            );
        }
        if request.destination() != generation.destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestDestinationMismatch {
                    source_address: generation.source(),
                    generation_destination: generation.destination(),
                    request_destination: request.destination(),
                },
            );
        }
        if request.action() != generation.action() {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestActionMismatch {
                    source_address: generation.source(),
                    destination: generation.destination(),
                    generation_action: generation.action(),
                    request_action: request.action(),
                },
            );
        }

        let expected_generation = validated_destination_request_generation(request)?;
        if generation.generation() != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteGenerationMismatch {
                    source_address: generation.source(),
                    destination: generation.destination(),
                    expected: expected_generation,
                    actual: generation.generation(),
                    action: request.action(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_boundary_minor_gc_object_generation_write_bindings(
    bindings: &[EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding],
) -> Result<(), EvalHeapError> {
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[..index]
            .iter()
            .any(|existing| existing.source() == binding.source())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestinationSource {
                    index,
                    source_address: binding.source(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn object_generation_write_generation_matches_binding(
    generation: &EvalGcStressBoundaryMinorGcLiveObjectGeneration,
    binding: &EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding,
) -> bool {
    generation.source() == binding.source()
        && generation.destination() == binding.destination()
        && generation.action() == binding.action()
        && generation.generation() == binding.generation()
        && generation.request() == binding.request()
}

pub(crate) fn object_generation_write_matches_binding(
    write: &EvalGcStressBoundaryMinorGcObjectGenerationWrite,
    binding: &EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding,
) -> bool {
    write.source() == binding.source()
        && write.destination() == binding.destination()
        && write.action() == binding.action()
        && write.generation() == binding.generation()
        && write.request() == binding.request()
}

pub(crate) fn apply_boundary_minor_gc_live_object_bodies(
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectBodyWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_body_heap_write_plan(plan)?;
    let report = heap.apply_collector_poll_minor_gc_object_body_writes(&heap_plan)?;
    debug_assert_eq!(report.objects(), plan.report().objects());
    debug_assert_eq!(
        report.copied_to_nursery(),
        plan.report().copied_to_nursery()
    );
    debug_assert_eq!(report.promoted_to_old(), plan.report().promoted_to_old());
    debug_assert_eq!(report.payload_bytes(), plan.report().payload_bytes());
    Ok(report)
}

pub(crate) fn apply_boundary_minor_gc_live_object_generations(
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_generation_heap_write_plan(plan)?;
    let report = heap.apply_collector_poll_minor_gc_object_generation_writes(&heap_plan)?;
    debug_assert_eq!(report.objects(), plan.report().objects());
    debug_assert_eq!(
        report.copied_to_nursery(),
        plan.report().copied_to_nursery()
    );
    debug_assert_eq!(report.promoted_to_old(), plan.report().promoted_to_old());
    debug_assert_eq!(report.payload_bytes(), plan.report().payload_bytes());
    Ok(report)
}

pub(crate) fn apply_boundary_minor_gc_live_object_bodies_and_generations(
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_body_heap_write_plan(plan)?;
    let report =
        heap.apply_collector_poll_minor_gc_object_body_and_generation_writes(&heap_plan)?;
    debug_assert_eq!(
        report.body_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.generation_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.body_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    debug_assert_eq!(
        report.generation_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    Ok(report)
}

pub(crate) fn validate_boundary_minor_gc_live_object_bodies_and_generations(
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_body_heap_write_plan(plan)?;
    let report =
        heap.validate_collector_poll_minor_gc_object_body_and_generation_writes(&heap_plan)?;
    debug_assert_eq!(
        report.body_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.generation_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.body_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    debug_assert_eq!(
        report.generation_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    Ok(report)
}

pub(crate) fn boundary_minor_gc_object_body_heap_write_plan(
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;
    requests.extend(plan.writes().iter().map(|write| write.request()));
    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

pub(crate) fn boundary_minor_gc_object_generation_heap_write_plan(
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectGenerationWritePlan, EvalHeapError> {
    boundary_minor_gc_object_body_heap_write_plan(plan)?.object_generation_write_plan()
}

pub(crate) fn validate_boundary_minor_gc_destination_generation_objects(
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    for (index, object) in destination_objects.iter().enumerate() {
        let _ = validated_destination_object_generation(object)?;
        if let Some(existing) = destination_objects[..index]
            .iter()
            .find(|existing| existing.destination() == object.destination())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveDestinationStorageDestinationCollision {
                    source_address: object.source(),
                    existing_source_address: existing.source(),
                    destination_address: object.destination(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn boundary_minor_gc_forwarding_destination_bindings(
    heap: &EvalHeap,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_forwarding_destination_bindings_from_heap_and_slots(
        heap,
        &[],
        destination_storage.object_bytes(),
    )
}

pub(crate) fn boundary_minor_gc_forwarding_destination_bindings_from_heap_and_slots(
    heap: &EvalHeap,
    forwarding_slots: &[MinorGcForwardingSlot],
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
    let forwarding_values = heap.minor_gc_forwarding_values()?;
    let combined_len = forwarding_values
        .len()
        .checked_add(forwarding_slots.len())
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
        })?;
    let mut combined_slots = Vec::new();
    combined_slots
        .try_reserve_exact(combined_len)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
            entries: combined_len,
        })?;

    for forwarding_value in forwarding_values {
        combined_slots.push(MinorGcForwardingSlot::with_forwarded_value(
            forwarding_value.source(),
            forwarding_value.forwarded_value(),
        ));
    }
    combined_slots.extend_from_slice(forwarding_slots);

    boundary_minor_gc_forwarding_destination_bindings_from_slots(
        &combined_slots,
        destination_objects,
    )
}

pub(crate) fn boundary_minor_gc_forwarding_destination_bindings_from_slots(
    forwarding_slots: &[MinorGcForwardingSlot],
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
    validate_boundary_minor_gc_destination_generation_objects(destination_objects)?;
    for object in destination_objects {
        if !forwarding_slots
            .iter()
            .any(|slot| slot.source() == object.source())
        {
            return Err(EvalHeapError::BoundaryMinorGcDestinationForwardingMissing {
                source_address: object.source(),
                destination: object.destination(),
            });
        }
    }

    validate_boundary_minor_gc_forwarding_slot_sources(forwarding_slots, destination_objects)?;

    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(forwarding_slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
            entries: forwarding_slots.len(),
        })?;

    for (index, slot) in forwarding_slots.iter().enumerate() {
        if forwarding_slots[..index]
            .iter()
            .any(|existing| existing.source() == slot.source())
        {
            return Err(EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
                index,
                address: slot.source(),
            });
        }
        let Some(forwarded_value) = slot.forwarded_value() else {
            return Err(EvalHeapError::CollectorPollForwardingSlotEmpty {
                index,
                address: slot.source(),
            });
        };
        let ResolvedValueGeneration::Heap {
            address: destination,
            generation,
        } = forwarded_value
        else {
            return Err(EvalHeapError::BoundaryMinorGcForwardingDestinationNonHeap {
                source_address: slot.source(),
                actual: forwarded_value,
            });
        };
        let destination_object = destination_objects
            .iter()
            .find(|object| object.source() == slot.source())
            .ok_or(EvalHeapError::BoundaryMinorGcForwardingDestinationMissing {
                source_address: slot.source(),
            })?;
        if destination != destination_object.destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingDestinationMismatch {
                    source_address: slot.source(),
                    expected: destination_object.destination(),
                    actual: destination,
                },
            );
        }
        let expected_generation = validated_destination_object_generation(destination_object)?;
        if generation != expected_generation {
            return Err(EvalHeapError::BoundaryMinorGcForwardingGenerationMismatch {
                source_address: slot.source(),
                destination,
                expected: expected_generation,
                actual: generation,
                action: destination_object.request().action(),
            });
        }

        bindings.push(
            EvalGcStressBoundaryMinorGcForwardingDestinationBinding::new(
                slot.source(),
                destination,
                generation,
                forwarded_value,
                destination_object.request(),
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
                    destination_object.destination_bytes(),
                )?,
            ),
        );
    }

    Ok(bindings)
}

pub(crate) fn boundary_minor_gc_forwarding_header_write_plan(
    heap: &EvalHeap,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan, EvalHeapError> {
    let bindings = live_bindings.forwarding_destination_bindings();
    let forwarding_values = heap.minor_gc_forwarding_values()?;

    for forwarding_value in forwarding_values.iter().copied() {
        if !bindings
            .iter()
            .any(|binding| binding.source() == forwarding_value.source())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingHeaderWriteUnboundForwarding {
                    source_address: forwarding_value.source(),
                    actual: forwarding_value.forwarded_value(),
                },
            );
        }
    }

    let mut writes = Vec::new();
    writes.try_reserve_exact(bindings.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITES_TABLE,
            entries: bindings.len(),
        }
    })?;

    for binding in bindings {
        let expected = binding.forwarded_value();
        let Some(actual) = heap.minor_gc_forwarding_value_at(binding.source())? else {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingHeaderWriteMissingForwarding {
                    source_address: binding.source(),
                    expected,
                },
            );
        };
        if actual != expected {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingHeaderWriteForwardingMismatch {
                    source_address: binding.source(),
                    expected,
                    actual,
                },
            );
        }

        writes.push(EvalGcStressBoundaryMinorGcForwardingHeaderWrite::from_binding(binding)?);
    }

    Ok(EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan::new(
        writes,
    ))
}

pub(crate) fn validate_boundary_minor_gc_existing_destination_commit_forwarding_header_coverage(
    report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    installed_references: usize,
) -> Result<(), EvalHeapError> {
    if installed_references != 0 && report.headers() == 0 {
        return Err(
            EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingForwardingHeaders {
                references: installed_references,
                forwarding_headers: report.headers(),
            },
        );
    }

    Ok(())
}
