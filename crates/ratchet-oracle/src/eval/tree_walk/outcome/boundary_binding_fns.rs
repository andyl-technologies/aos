//! Root and heap-field writeback destination-binding builders and generation validation helpers.

use super::*;

pub(crate) fn boundary_minor_gc_root_writeback_destination_bindings(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_root_writeback_destination_bindings_from_applications(
        writebacks.applications(),
        destination_storage.object_bytes(),
    )
}

pub(crate) fn boundary_minor_gc_root_writeback_destination_bindings_from_applications(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>, EvalHeapError> {
    let mut bindings = Vec::new();
    extend_boundary_minor_gc_root_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::Worker,
        applications.worker(),
        destination_objects,
    )?;
    extend_boundary_minor_gc_root_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
        destination_objects,
    )?;
    Ok(bindings)
}

pub(crate) fn extend_boundary_minor_gc_root_writeback_destination_bindings(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    let root_slots = application.root_writeback_slots();
    let value_slots = application.root_value_writeback_slots();
    if root_slots.len() != value_slots.len() {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected: root_slots.len(),
                actual: value_slots.len(),
            },
        );
    }

    for (index, (root_slot, value_slot)) in root_slots.iter().zip(value_slots.iter()).enumerate() {
        if root_slot.source() != value_slot.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index,
                expected: root_slot.source().clone(),
                actual: value_slot.source().clone(),
            });
        }
        let ResolvedValueGeneration::Heap {
            address: destination,
            generation,
        } = root_slot.value()
        else {
            return Err(EvalHeapError::CollectorPollRootWritebackNonHeapValue {
                tag: value_slot.value().tag(),
                value: root_slot.value(),
            });
        };
        let replacement = value_slot.value();
        let replacement_ptr = replacement.as_heap_ptr().map_err(EvalHeapError::Value)?;
        let replacement_destination = GcHeapAddress::new(replacement_ptr.as_ptr() as usize)
            .map_err(EvalHeapError::GenerationalGc)?;
        if replacement_destination != destination {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackDestinationMismatch {
                    root_source: root_slot.source().clone(),
                    expected_destination: destination,
                    actual_tag: replacement.tag(),
                    actual_payload: replacement.payload_bits(),
                },
            );
        }

        let destination_object = destination_objects
            .iter()
            .find(|object| object.destination() == destination)
            .ok_or_else(
                || EvalHeapError::BoundaryMinorGcRootWritebackDestinationMissing {
                    root_source: root_slot.source().clone(),
                    destination,
                },
            )?;
        let expected_generation = validated_destination_object_generation(destination_object)?;
        if generation != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackGenerationMismatch {
                    root_source: root_slot.source().clone(),
                    destination,
                    expected: expected_generation,
                    actual: generation,
                    action: destination_object.request().action(),
                },
            );
        }

        let entries =
            bindings
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                })?;
        bindings
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                entries,
            })?;
        bindings.push(
            EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
                allocation_domain,
                root_slot.source().clone(),
                replacement.tag(),
                destination,
                generation,
                destination_object.request(),
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                    destination_object.destination_bytes(),
                )?,
            ),
        );
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn boundary_minor_gc_heap_field_writeback_destination_bindings(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications(
        writebacks.applications(),
        destination_storage.object_bytes(),
    )
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
    heap: &EvalHeap,
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
        heap,
        writebacks.applications(),
        destination_storage.object_bytes(),
    )
}

#[cfg(test)]
pub(crate) fn boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    let mut bindings = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::Worker,
        applications.worker(),
        destination_objects,
    )?;
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
        destination_objects,
    )?;
    Ok(bindings)
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
    heap: &EvalHeap,
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    let mut bindings = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
        &mut bindings,
        heap,
        applications.worker(),
        destination_objects,
    )?;
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
        &mut bindings,
        heap,
        applications.permanent_shared(),
        destination_objects,
    )?;
    Ok(bindings)
}

#[cfg(test)]
pub(crate) fn extend_boundary_minor_gc_heap_field_writeback_destination_bindings(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
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

        let replacement_object = destination_objects
            .iter()
            .find(|object| object.destination() == replacement_destination)
            .ok_or_else(
                || EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementMissing {
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                    replacement: replacement_destination,
                },
            )?;
        let expected_generation = validated_destination_object_generation(replacement_object)?;
        if replacement_generation != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                    replacement: replacement_destination,
                    expected: expected_generation,
                    actual: replacement_generation,
                    action: replacement_object.request().action(),
                },
            );
        }

        let writeback_object_destination = if slot.validation_object() != slot.writeback_object() {
            let Some(object) = destination_objects
                .iter()
                .find(|object| object.destination() == slot.writeback_object())
            else {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectMissing {
                        validation_object: slot.validation_object(),
                        writeback_object: slot.writeback_object(),
                        field_index: slot.field_index(),
                        field_source: slot.source().clone(),
                    },
                );
            };
            if object.source() != slot.validation_object() {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectSourceMismatch {
                        validation_object: slot.validation_object(),
                        writeback_object: slot.writeback_object(),
                        field_index: slot.field_index(),
                        field_source: slot.source().clone(),
                        actual_source: object.source(),
                    },
                );
            }
            let _ = validated_destination_object_generation(object)?;
            Some(object)
        } else {
            None
        };

        let entries =
            bindings
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                })?;
        bindings
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                entries,
            })?;
        let replacement_destination_bytes = clone_boundary_destination_storage_bytes(
            BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
            replacement_object.destination_bytes(),
        )?;
        let writeback_object_request = writeback_object_destination
            .map(EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::request);
        let writeback_object_destination_bytes = writeback_object_destination
            .map(|object| {
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                    object.destination_bytes(),
                )
            })
            .transpose()?;
        bindings.push(
            EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
                allocation_domain,
                slot.validation_object(),
                slot.writeback_object(),
                slot.field_index(),
                slot.source().clone(),
                replacement_destination,
                replacement_generation,
                replacement_object.request(),
                replacement_destination_bytes,
                writeback_object_request,
                writeback_object_destination_bytes,
            ),
        );
    }

    Ok(())
}

pub(crate) fn extend_boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    heap: &EvalHeap,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for slot in application.heap_field_writeback_slots() {
        let allocation_domain = heap_field_writeback_slot_allocation_domain(heap, slot)?;
        extend_boundary_minor_gc_heap_field_writeback_destination_binding(
            bindings,
            allocation_domain,
            slot,
            destination_objects,
        )?;
    }

    Ok(())
}

pub(crate) fn extend_boundary_minor_gc_heap_field_writeback_destination_binding(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    allocation_domain: HeapAllocationDomain,
    slot: &AllocationCollectorPollHeapFieldWritebackSlot,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
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

    let replacement_object = destination_objects
        .iter()
        .find(|object| object.destination() == replacement_destination)
        .ok_or_else(
            || EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementMissing {
                writeback_object: slot.writeback_object(),
                field_index: slot.field_index(),
                field_source: slot.source().clone(),
                replacement: replacement_destination,
            },
        )?;
    let expected_generation = validated_destination_object_generation(replacement_object)?;
    if replacement_generation != expected_generation {
        return Err(
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                writeback_object: slot.writeback_object(),
                field_index: slot.field_index(),
                field_source: slot.source().clone(),
                replacement: replacement_destination,
                expected: expected_generation,
                actual: replacement_generation,
                action: replacement_object.request().action(),
            },
        );
    }

    let writeback_object_destination = if slot.validation_object() != slot.writeback_object() {
        let Some(object) = destination_objects
            .iter()
            .find(|object| object.destination() == slot.writeback_object())
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectMissing {
                    validation_object: slot.validation_object(),
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                },
            );
        };
        if object.source() != slot.validation_object() {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectSourceMismatch {
                    validation_object: slot.validation_object(),
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                    actual_source: object.source(),
                },
            );
        }
        let _ = validated_destination_object_generation(object)?;
        Some(object)
    } else {
        None
    };

    let replacement_destination_bytes = clone_boundary_destination_storage_bytes(
        BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
        replacement_object.destination_bytes(),
    )?;
    let writeback_object_request = writeback_object_destination
        .map(EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::request);
    let writeback_object_destination_bytes = writeback_object_destination
        .map(|object| {
            clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                object.destination_bytes(),
            )
        })
        .transpose()?;
    let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
        allocation_domain,
        slot.validation_object(),
        slot.writeback_object(),
        slot.field_index(),
        slot.source().clone(),
        replacement_destination,
        replacement_generation,
        replacement_object.request(),
        replacement_destination_bytes,
        writeback_object_request,
        writeback_object_destination_bytes,
    );
    if bindings.iter().any(|existing| existing == &binding) {
        return Ok(());
    }

    let entries = bindings
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
        })?;
    bindings
        .try_reserve_exact(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
            entries,
        })?;
    bindings.push(binding);

    Ok(())
}

pub(crate) fn heap_field_writeback_slot_allocation_domain(
    heap: &EvalHeap,
    slot: &AllocationCollectorPollHeapFieldWritebackSlot,
) -> Result<HeapAllocationDomain, EvalHeapError> {
    let (address, role) = if slot.validation_object() == slot.writeback_object() {
        (slot.writeback_object(), "heap-field writeback object")
    } else {
        (slot.validation_object(), "heap-field validation object")
    };
    heap.allocation_domain_for_address(address, role)
}

pub(crate) const fn generation_for_destination_action(
    action: MinorGcSurvivorAction,
) -> HeapGeneration {
    match action {
        MinorGcSurvivorAction::CopyToNursery => HeapGeneration::Young,
        MinorGcSurvivorAction::PromoteToOld => HeapGeneration::Old,
    }
}

pub(crate) fn validated_destination_request_generation(
    request: AllocationCollectorPollObjectByteCopyRequest,
) -> Result<HeapGeneration, EvalHeapError> {
    let expected = generation_for_destination_action(request.action());
    let actual = request.destination_generation();
    if actual != expected {
        return Err(
            EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
                destination: request.destination(),
                expected,
                actual,
                action: request.action(),
            },
        );
    }

    Ok(expected)
}

pub(crate) fn validated_destination_object_generation(
    object: &EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes,
) -> Result<HeapGeneration, EvalHeapError> {
    let generation = validated_destination_request_generation(object.request())?;
    let expected = object.request().size_bytes();
    let actual = object.destination_bytes().len();
    if actual != expected {
        return Err(
            EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                destination: object.destination(),
                expected,
                actual,
            },
        );
    }

    Ok(generation)
}
