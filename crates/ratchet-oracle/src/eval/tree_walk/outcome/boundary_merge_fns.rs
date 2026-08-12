//! Boundary snapshot clone/merge helpers and relocation-consistency validators.

use super::*;

pub(crate) fn clone_boundary_forwarding_slots(
    slots: &[MinorGcForwardingSlot],
) -> Result<Vec<MinorGcForwardingSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().copied());
    Ok(cloned)
}

pub(crate) fn clone_boundary_reference_buffer(
    references: &[ResolvedValueGeneration],
) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned.try_reserve_exact(references.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_REFERENCE_BUFFER_TABLE,
            entries: references.len(),
        }
    })?;
    cloned.extend(references.iter().copied());
    Ok(cloned)
}

pub(crate) fn clone_boundary_reference_writeback_applications(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplications, EvalHeapError> {
    let worker = applications
        .worker()
        .map(clone_boundary_reference_writeback_application)
        .transpose()?;
    let permanent_shared = applications
        .permanent_shared()
        .map(clone_boundary_reference_writeback_application)
        .transpose()?;
    Ok(EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(worker, permanent_shared))
}

pub(crate) fn clone_boundary_reference_writeback_application(
    application: &EvalGcStressBoundaryMinorGcReferenceWritebackApplication,
) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplication, EvalHeapError> {
    Ok(
        EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
            application.report(),
            clone_boundary_live_root_writeback_slots(application.root_writeback_slots())?,
            clone_boundary_live_root_value_writeback_slots(
                application.root_value_writeback_slots(),
            )?,
            clone_boundary_live_heap_field_writeback_slots(
                application.heap_field_writeback_slots(),
            )?,
        ),
    )
}

pub(crate) fn clone_boundary_live_root_writeback_slots(
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_ROOT_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

pub(crate) fn clone_boundary_live_root_value_writeback_slots(
    slots: &[AllocationCollectorPollRootValueWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootValueWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_ROOT_VALUE_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

pub(crate) fn clone_boundary_live_heap_field_writeback_slots(
    slots: &[AllocationCollectorPollHeapFieldWritebackSlot],
) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_HEAP_FIELD_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

pub(crate) fn clone_boundary_remembered_set(
    remembered_set: &RememberedSet,
) -> Result<RememberedSet, EvalHeapError> {
    let mut cloned = RememberedSet::with_epoch(remembered_set.epoch());
    for edge in remembered_set.edges() {
        cloned.record(*edge)?;
    }
    Ok(cloned)
}

pub(crate) fn boundary_minor_gc_merged_destination_object_bytes(
    applications: &EvalGcStressBoundaryMinorGcCommitApplications,
) -> Result<Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>, EvalHeapError> {
    let mut merged = Vec::new();
    merge_boundary_minor_gc_destination_object_bytes_application(
        &mut merged,
        applications.worker(),
    )?;
    merge_boundary_minor_gc_destination_object_bytes_application(
        &mut merged,
        applications.permanent_shared(),
    )?;
    Ok(merged)
}

pub(crate) fn merge_boundary_minor_gc_destination_object_bytes_application(
    merged: &mut Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
    application: Option<&EvalGcStressBoundaryMinorGcCommitApplication>,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for object_copy in application.object_byte_copies() {
        let request = object_copy.request();
        if let Some(existing) = merged
            .iter()
            .find(|existing| existing.source() == request.source())
        {
            if existing.request() != request
                || existing.destination_bytes() != object_copy.destination_bytes()
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveDestinationStorageObjectMismatch {
                        source_address: request.source(),
                        expected: existing.request(),
                        actual: request,
                    },
                );
            }
            continue;
        }

        if let Some(existing) = merged
            .iter()
            .find(|existing| existing.destination() == request.destination())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveDestinationStorageDestinationCollision {
                    source_address: request.source(),
                    existing_source_address: existing.source(),
                    destination_address: request.destination(),
                },
            );
        }

        let entries = merged
            .len()
            .checked_add(1)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE,
            })?;
        merged
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE,
                entries,
            })?;
        merged.push(EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(
            request,
            clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE,
                object_copy.destination_bytes(),
            )?,
        ));
    }

    Ok(())
}

pub(crate) fn boundary_minor_gc_merged_forwarding_slots(
    applications: &EvalGcStressBoundaryMinorGcCommitApplications,
) -> Result<Vec<MinorGcForwardingSlot>, EvalHeapError> {
    let mut relocations = Vec::new();
    merge_boundary_minor_gc_forwarding_slot_application(&mut relocations, applications.worker())?;
    merge_boundary_minor_gc_forwarding_slot_application(
        &mut relocations,
        applications.permanent_shared(),
    )?;

    let mut slots = Vec::new();
    slots.try_reserve_exact(relocations.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
            entries: relocations.len(),
        }
    })?;
    for (source, forwarded) in relocations {
        slots.push(MinorGcForwardingSlot::with_forwarded_value(
            source, forwarded,
        ));
    }
    Ok(slots)
}

pub(crate) fn merge_boundary_minor_gc_forwarding_slot_application(
    relocations: &mut Vec<(GcHeapAddress, ResolvedValueGeneration)>,
    application: Option<&EvalGcStressBoundaryMinorGcCommitApplication>,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    validate_boundary_minor_gc_relocations_match(relocations, application.forwarding_slots())
}

pub(crate) fn boundary_minor_gc_merged_remembered_set(
    applications: &EvalGcStressBoundaryMinorGcCommitApplications,
    source_epoch: RememberedSetEpoch,
) -> Result<Option<RememberedSet>, EvalHeapError> {
    let mut merged = None;
    let mut relocations = Vec::new();
    merge_boundary_minor_gc_remembered_set_application(
        &mut merged,
        &mut relocations,
        applications.worker(),
        source_epoch,
    )?;
    merge_boundary_minor_gc_remembered_set_application(
        &mut merged,
        &mut relocations,
        applications.permanent_shared(),
        source_epoch,
    )?;
    Ok(merged)
}

pub(crate) fn merge_boundary_minor_gc_remembered_set_application(
    merged: &mut Option<RememberedSet>,
    relocations: &mut Vec<(GcHeapAddress, ResolvedValueGeneration)>,
    application: Option<&EvalGcStressBoundaryMinorGcCommitApplication>,
    source_epoch: RememberedSetEpoch,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    let expected_next_epoch = source_epoch.checked_next()?;
    let report = application.report();
    if report.remembered_set_source_epoch() != source_epoch {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetSourceEpochMismatch {
                expected: source_epoch,
                actual: report.remembered_set_source_epoch(),
            },
        );
    }
    if report.remembered_set_next_epoch() != expected_next_epoch {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
                expected: expected_next_epoch,
                actual: report.remembered_set_next_epoch(),
            },
        );
    }

    let application_set = application.remembered_set();
    if application_set.epoch() != expected_next_epoch {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
                expected: expected_next_epoch,
                actual: application_set.epoch(),
            },
        );
    }
    validate_boundary_minor_gc_relocations_match(relocations, application.forwarding_slots())?;

    match merged {
        Some(merged_set) => {
            if merged_set.epoch() != application_set.epoch() {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
                        expected: merged_set.epoch(),
                        actual: application_set.epoch(),
                    },
                );
            }
            for edge in application_set.edges() {
                merged_set.record(*edge)?;
            }
        }
        None => {
            let mut merged_set = RememberedSet::with_epoch(expected_next_epoch);
            for edge in application_set.edges() {
                merged_set.record(*edge)?;
            }
            *merged = Some(merged_set);
        }
    }

    Ok(())
}

pub(crate) fn validate_boundary_minor_gc_relocations_match(
    relocations: &mut Vec<(GcHeapAddress, ResolvedValueGeneration)>,
    forwarding_slots: &[MinorGcForwardingSlot],
) -> Result<(), EvalHeapError> {
    let mut application_sources = Vec::new();
    for slot in forwarding_slots {
        if slot.forwarded_value().is_none() {
            continue;
        }
        let entries = application_sources.len().checked_add(1).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
            },
        )?;
        application_sources.try_reserve_exact(1).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries,
            }
        })?;
        application_sources.push(slot.source());
    }

    for slot in forwarding_slots {
        let Some(forwarded) = slot.forwarded_value() else {
            continue;
        };
        validate_boundary_minor_gc_source_not_destination(slot.source(), relocations)?;
        validate_boundary_minor_gc_destination_not_source(
            forwarded,
            relocations,
            &application_sources,
        )?;
        if let Some((_, expected)) = relocations
            .iter()
            .find(|(source, _)| *source == slot.source())
        {
            if *expected != forwarded {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveRememberedSetRelocationMismatch {
                        source_address: slot.source(),
                        expected: *expected,
                        actual: forwarded,
                    },
                );
            }
            continue;
        }
        if let Some(forwarded_address) = resolved_heap_address(forwarded) {
            if let Some((existing_source, _)) = relocations.iter().find(|(_, destination)| {
                resolved_heap_address(*destination) == Some(forwarded_address)
            }) {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationCollision {
                        source_address: slot.source(),
                        existing_source_address: *existing_source,
                        destination: forwarded,
                    },
                );
            }
        }
        let entries =
            relocations
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                })?;
        relocations
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries,
            })?;
        relocations.push((slot.source(), forwarded));
    }
    Ok(())
}

pub(crate) fn validate_boundary_minor_gc_source_not_destination(
    source: GcHeapAddress,
    relocations: &[(GcHeapAddress, ResolvedValueGeneration)],
) -> Result<(), EvalHeapError> {
    let Some((_, destination)) = relocations
        .iter()
        .find(|(_, destination)| resolved_heap_address(*destination) == Some(source))
    else {
        return Ok(());
    };

    Err(
        EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
            source_address: source,
            destination: *destination,
        },
    )
}

pub(crate) fn validate_boundary_minor_gc_destination_not_source(
    forwarded: ResolvedValueGeneration,
    relocations: &[(GcHeapAddress, ResolvedValueGeneration)],
    application_sources: &[GcHeapAddress],
) -> Result<(), EvalHeapError> {
    let Some(destination) = resolved_heap_address(forwarded) else {
        return Ok(());
    };

    if relocations.iter().any(|(source, _)| *source == destination)
        || application_sources
            .iter()
            .any(|source| *source == destination)
    {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
                source_address: destination,
                destination: forwarded,
            },
        );
    }

    Ok(())
}

pub(crate) fn resolved_heap_address(value: ResolvedValueGeneration) -> Option<GcHeapAddress> {
    let ResolvedValueGeneration::Heap { address, .. } = value else {
        return None;
    };

    Some(address)
}

pub(crate) fn clone_boundary_root_writeback_slots(
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

pub(crate) fn clone_boundary_root_value_writeback_slots(
    slots: &[AllocationCollectorPollRootValueWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootValueWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_VALUE_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

pub(crate) fn clone_boundary_heap_field_writeback_slots(
    slots: &[AllocationCollectorPollHeapFieldWritebackSlot],
) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}
