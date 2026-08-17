//! Heap-field writeback write-source planning, validation, and matching helpers.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct BoundaryMinorGcHeapFieldWritebackWriteSource {
    pub(crate) allocation_domain: HeapAllocationDomain,
    pub(crate) validation_object: GcHeapAddress,
    pub(crate) writeback_object: GcHeapAddress,
    pub(crate) field_index: usize,
    pub(crate) source: HeapEdgeSource,
    pub(crate) replacement_destination: GcHeapAddress,
    pub(crate) replacement_generation: HeapGeneration,
    pub(crate) replacement_metadata: ResolvedValueGeneration,
}

#[cfg(test)]
pub(crate) fn boundary_minor_gc_heap_field_writeback_write_plan(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
    let sources = boundary_minor_gc_heap_field_writeback_write_sources(writebacks.applications())?;
    boundary_minor_gc_heap_field_writeback_write_plan_from_sources(sources, live_bindings)
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_write_plan_for_heap(
    heap: &EvalHeap,
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
    let sources = boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
        heap,
        writebacks.applications(),
    )?;
    boundary_minor_gc_heap_field_writeback_write_plan_from_sources(sources, live_bindings)
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_write_plan_from_sources(
    sources: Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
    let bindings = live_bindings.heap_field_writeback_bindings();
    validate_boundary_minor_gc_heap_field_writeback_write_sources(&sources)?;
    validate_boundary_minor_gc_heap_field_writeback_write_bindings(bindings)?;
    let mut writes = Vec::new();
    writes.try_reserve_exact(sources.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries: sources.len(),
        }
    })?;

    for source in sources {
        let Some(binding) = bindings
            .iter()
            .find(|binding| heap_field_writeback_write_source_matches_binding(&source, binding))
        else {
            if let Some(binding) = bindings.iter().find(|binding| {
                heap_field_writeback_write_source_matches_binding_identity(&source, binding)
            }) {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteBindingMismatch {
                        allocation_domain: source.allocation_domain,
                        writeback_object: source.writeback_object,
                        field_index: source.field_index,
                        field_source: source.source,
                        expected_replacement: source.replacement_destination,
                        expected_generation: source.replacement_generation,
                        actual_replacement: binding.replacement_destination(),
                        actual_generation: binding.replacement_generation(),
                    },
                );
            }

            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteMissingBinding {
                    allocation_domain: source.allocation_domain,
                    writeback_object: source.writeback_object,
                    field_index: source.field_index,
                    field_source: source.source,
                    replacement: source.replacement_destination,
                    generation: source.replacement_generation,
                },
            );
        };

        writes.push(
            EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite::from_source_and_binding(
                source, binding,
            )?,
        );
    }

    for binding in bindings {
        if !writes
            .iter()
            .any(|write| heap_field_writeback_write_matches_binding(write, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteUnboundBinding {
                    allocation_domain: binding.allocation_domain(),
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                    replacement: binding.replacement_destination(),
                    generation: binding.replacement_generation(),
                },
            );
        }
    }

    Ok(EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan::new(
        writes,
    ))
}

#[cfg(test)]
pub(crate) fn boundary_minor_gc_heap_field_writeback_write_sources(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>, EvalHeapError> {
    let mut sources = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::Worker,
        applications.worker(),
    )?;
    extend_boundary_minor_gc_heap_field_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
    )?;
    Ok(sources)
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
    heap: &EvalHeap,
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>, EvalHeapError> {
    let mut sources = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
        &mut sources,
        heap,
        applications.worker(),
    )?;
    extend_boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
        &mut sources,
        heap,
        applications.permanent_shared(),
    )?;
    Ok(sources)
}

#[cfg(test)]
pub(crate) fn extend_boundary_minor_gc_heap_field_writeback_write_sources(
    sources: &mut Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for slot in application.heap_field_writeback_slots() {
        let ResolvedValueGeneration::Heap {
            address: replacement_destination,
            generation: replacement_generation,
        } = slot.value()
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                    value: slot.value(),
                },
            );
        };

        let entries =
            sources
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
                })?;
        sources
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
                entries,
            })?;
        sources.push(BoundaryMinorGcHeapFieldWritebackWriteSource {
            allocation_domain,
            validation_object: slot.validation_object(),
            writeback_object: slot.writeback_object(),
            field_index: slot.field_index(),
            source: slot.source().clone(),
            replacement_destination,
            replacement_generation,
            replacement_metadata: slot.value(),
        });
    }

    Ok(())
}

pub(crate) fn extend_boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
    sources: &mut Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    heap: &EvalHeap,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for slot in application.heap_field_writeback_slots() {
        let allocation_domain = heap_field_writeback_slot_allocation_domain(heap, slot)?;
        extend_boundary_minor_gc_heap_field_writeback_write_source(
            sources,
            allocation_domain,
            slot,
        )?;
    }

    Ok(())
}

pub(crate) fn extend_boundary_minor_gc_heap_field_writeback_write_source(
    sources: &mut Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    allocation_domain: HeapAllocationDomain,
    slot: &AllocationCollectorPollHeapFieldWritebackSlot,
) -> Result<(), EvalHeapError> {
    let ResolvedValueGeneration::Heap {
        address: replacement_destination,
        generation: replacement_generation,
    } = slot.value()
    else {
        return Err(
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                writeback_object: slot.writeback_object(),
                field_index: slot.field_index(),
                field_source: slot.source().clone(),
                value: slot.value(),
            },
        );
    };

    let source = BoundaryMinorGcHeapFieldWritebackWriteSource {
        allocation_domain,
        validation_object: slot.validation_object(),
        writeback_object: slot.writeback_object(),
        field_index: slot.field_index(),
        source: slot.source().clone(),
        replacement_destination,
        replacement_generation,
        replacement_metadata: slot.value(),
    };
    if sources
        .iter()
        .any(|existing| heap_field_writeback_write_source_matches(existing, &source))
    {
        return Ok(());
    }

    let entries = sources
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
        })?;
    sources
        .try_reserve_exact(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries,
        })?;
    sources.push(source);

    Ok(())
}

pub(crate) fn validate_boundary_minor_gc_heap_field_writeback_write_sources(
    sources: &[BoundaryMinorGcHeapFieldWritebackWriteSource],
) -> Result<(), EvalHeapError> {
    for (index, source) in sources.iter().enumerate() {
        if sources[..index]
            .iter()
            .any(|existing| heap_field_writeback_write_source_identity_matches(existing, source))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                    index,
                    allocation_domain: source.allocation_domain,
                    writeback_object: source.writeback_object,
                    field_index: source.field_index,
                    field_source: source.source.clone(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_boundary_minor_gc_heap_field_writeback_write_bindings(
    bindings: &[EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding],
) -> Result<(), EvalHeapError> {
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[..index]
            .iter()
            .any(|existing| heap_field_writeback_write_binding_identity_matches(existing, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateBinding {
                    index,
                    allocation_domain: binding.allocation_domain(),
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                },
            );
        }

        let replacement_request = binding.replacement_request();
        if replacement_request.destination() != binding.replacement_destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteReplacementRequestDestinationMismatch {
                    allocation_domain: binding.allocation_domain(),
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                    binding_replacement: binding.replacement_destination(),
                    request_destination: replacement_request.destination(),
                },
            );
        }
        let expected_generation = validated_destination_request_generation(replacement_request)?;
        if binding.replacement_generation() != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                    replacement: binding.replacement_destination(),
                    expected: expected_generation,
                    actual: binding.replacement_generation(),
                    action: replacement_request.action(),
                },
            );
        }
        if binding.replacement_destination_bytes().len() != replacement_request.size_bytes() {
            return Err(
                EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                    destination: binding.replacement_destination(),
                    expected: replacement_request.size_bytes(),
                    actual: binding.replacement_destination_bytes().len(),
                },
            );
        }

        match (
            binding.validation_object() != binding.writeback_object(),
            binding.writeback_object_request(),
            binding.writeback_object_destination_bytes(),
        ) {
            (false, None, None) => {}
            (false, _, _) | (true, None, _) | (true, _, None) => {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectBindingMalformed {
                        allocation_domain: binding.allocation_domain(),
                        validation_object: binding.validation_object(),
                        writeback_object: binding.writeback_object(),
                        field_index: binding.field_index(),
                        field_source: binding.source().clone(),
                    },
                );
            }
            (true, Some(writeback_object_request), Some(bytes)) => {
                if writeback_object_request.source() != binding.validation_object() {
                    return Err(
                        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestSourceMismatch {
                            allocation_domain: binding.allocation_domain(),
                            validation_object: binding.validation_object(),
                            writeback_object: binding.writeback_object(),
                            field_index: binding.field_index(),
                            field_source: binding.source().clone(),
                            actual_source: writeback_object_request.source(),
                        },
                    );
                }
                if writeback_object_request.destination() != binding.writeback_object() {
                    return Err(
                        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestDestinationMismatch {
                            allocation_domain: binding.allocation_domain(),
                            validation_object: binding.validation_object(),
                            writeback_object: binding.writeback_object(),
                            field_index: binding.field_index(),
                            field_source: binding.source().clone(),
                            request_destination: writeback_object_request.destination(),
                        },
                    );
                }
                let _ = validated_destination_request_generation(writeback_object_request)?;
                if bytes.len() != writeback_object_request.size_bytes() {
                    return Err(
                        EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                            destination: binding.writeback_object(),
                            expected: writeback_object_request.size_bytes(),
                            actual: bytes.len(),
                        },
                    );
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn heap_field_writeback_write_source_matches_binding(
    source: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    heap_field_writeback_write_source_matches_binding_identity(source, binding)
        && source.replacement_destination == binding.replacement_destination()
        && source.replacement_generation == binding.replacement_generation()
}

pub(crate) fn heap_field_writeback_write_source_matches_binding_identity(
    source: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    source.allocation_domain == binding.allocation_domain()
        && source.validation_object == binding.validation_object()
        && source.writeback_object == binding.writeback_object()
        && source.field_index == binding.field_index()
        && source.source == *binding.source()
}

pub(crate) fn heap_field_writeback_write_matches_binding(
    write: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite,
    binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    write.allocation_domain() == binding.allocation_domain()
        && write.validation_object() == binding.validation_object()
        && write.writeback_object() == binding.writeback_object()
        && write.field_index() == binding.field_index()
        && write.source() == binding.source()
        && write.replacement_destination() == binding.replacement_destination()
        && write.replacement_generation() == binding.replacement_generation()
}

pub(crate) fn heap_field_writeback_write_source_identity_matches(
    left: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    right: &BoundaryMinorGcHeapFieldWritebackWriteSource,
) -> bool {
    left.allocation_domain == right.allocation_domain
        && left.validation_object == right.validation_object
        && left.writeback_object == right.writeback_object
        && left.field_index == right.field_index
        && left.source == right.source
}

pub(crate) fn heap_field_writeback_write_source_matches(
    left: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    right: &BoundaryMinorGcHeapFieldWritebackWriteSource,
) -> bool {
    heap_field_writeback_write_source_identity_matches(left, right)
        && left.replacement_destination == right.replacement_destination
        && left.replacement_generation == right.replacement_generation
        && left.replacement_metadata == right.replacement_metadata
}

pub(crate) fn heap_field_writeback_write_binding_identity_matches(
    left: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
    right: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    left.allocation_domain() == right.allocation_domain()
        && left.validation_object() == right.validation_object()
        && left.writeback_object() == right.writeback_object()
        && left.field_index() == right.field_index()
        && left.source() == right.source()
}

pub(crate) fn validate_boundary_minor_gc_forwarding_slot_sources(
    forwarding_slots: &[MinorGcForwardingSlot],
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
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
        if slot.forwarded_value().is_none() {
            return Err(EvalHeapError::CollectorPollForwardingSlotEmpty {
                index,
                address: slot.source(),
            });
        }
        if !destination_objects
            .iter()
            .any(|object| object.source() == slot.source())
        {
            return Err(EvalHeapError::BoundaryMinorGcForwardingDestinationMissing {
                source_address: slot.source(),
            });
        }
    }

    Ok(())
}
