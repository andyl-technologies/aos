//! Root-writeback and reference-writeback write planning, validation, apply, and commit helpers.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct BoundaryMinorGcRootWritebackWriteSource {
    pub(crate) allocation_domain: HeapAllocationDomain,
    pub(crate) root_source: EvalRootSource,
    pub(crate) replacement_tag: ValueTag,
    pub(crate) replacement_value: Value,
    pub(crate) destination: GcHeapAddress,
    pub(crate) generation: HeapGeneration,
    pub(crate) replacement_metadata: ResolvedValueGeneration,
}

pub(crate) fn boundary_minor_gc_root_writeback_write_plan(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcRootWritebackWritePlan, EvalHeapError> {
    let bindings = live_bindings.root_writeback_bindings();
    let sources = boundary_minor_gc_root_writeback_write_sources(writebacks.applications())?;
    validate_boundary_minor_gc_root_writeback_write_sources(&sources)?;
    validate_boundary_minor_gc_root_writeback_write_bindings(bindings)?;
    let mut writes = Vec::new();
    writes.try_reserve_exact(sources.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
            entries: sources.len(),
        }
    })?;

    for source in sources {
        let Some(binding) = bindings
            .iter()
            .find(|binding| root_writeback_write_source_matches_binding(&source, binding))
        else {
            if let Some(binding) = bindings.iter().find(|binding| {
                root_writeback_write_source_matches_binding_identity(&source, binding)
            }) {
                return Err(
                    EvalHeapError::BoundaryMinorGcRootWritebackWriteBindingMismatch {
                        allocation_domain: source.allocation_domain,
                        root_source: source.root_source,
                        expected_tag: source.replacement_tag,
                        expected_destination: source.destination,
                        expected_generation: source.generation,
                        actual_tag: binding.replacement_tag(),
                        actual_destination: binding.destination(),
                        actual_generation: binding.generation(),
                    },
                );
            }

            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteMissingBinding {
                    allocation_domain: source.allocation_domain,
                    root_source: source.root_source,
                    replacement_tag: source.replacement_tag,
                    destination: source.destination,
                    generation: source.generation,
                },
            );
        };

        writes.push(
            EvalGcStressBoundaryMinorGcRootWritebackWrite::from_source_and_binding(
                source, binding,
            )?,
        );
    }

    for binding in bindings {
        if !writes
            .iter()
            .any(|write| root_writeback_write_matches_binding(write, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteUnboundBinding {
                    allocation_domain: binding.allocation_domain(),
                    root_source: binding.root_source().clone(),
                    replacement_tag: binding.replacement_tag(),
                    destination: binding.destination(),
                    generation: binding.generation(),
                },
            );
        }
    }

    Ok(EvalGcStressBoundaryMinorGcRootWritebackWritePlan::new(
        writes,
    ))
}

pub(crate) fn validate_boundary_minor_gc_root_writeback_write_sources(
    sources: &[BoundaryMinorGcRootWritebackWriteSource],
) -> Result<(), EvalHeapError> {
    for (index, source) in sources.iter().enumerate() {
        if sources[..index].iter().any(|existing| {
            existing.allocation_domain == source.allocation_domain
                && existing.root_source == source.root_source
        }) {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateSource {
                    index,
                    allocation_domain: source.allocation_domain,
                    root_source: source.root_source.clone(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_boundary_minor_gc_root_writeback_write_bindings(
    bindings: &[EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding],
) -> Result<(), EvalHeapError> {
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[..index].iter().any(|existing| {
            existing.allocation_domain() == binding.allocation_domain()
                && existing.root_source() == binding.root_source()
        }) {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateBinding {
                    index,
                    allocation_domain: binding.allocation_domain(),
                    root_source: binding.root_source().clone(),
                },
            );
        }

        let request = binding.request();
        if request.destination() != binding.destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteRequestDestinationMismatch {
                    allocation_domain: binding.allocation_domain(),
                    root_source: binding.root_source().clone(),
                    binding_destination: binding.destination(),
                    request_destination: request.destination(),
                },
            );
        }

        let expected_generation = validated_destination_request_generation(request)?;
        if binding.generation() != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackGenerationMismatch {
                    root_source: binding.root_source().clone(),
                    destination: binding.destination(),
                    expected: expected_generation,
                    actual: binding.generation(),
                    action: request.action(),
                },
            );
        }

        if binding.destination_bytes().len() != request.size_bytes() {
            return Err(
                EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                    destination: binding.destination(),
                    expected: request.size_bytes(),
                    actual: binding.destination_bytes().len(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn boundary_minor_gc_root_writeback_write_sources(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<Vec<BoundaryMinorGcRootWritebackWriteSource>, EvalHeapError> {
    let mut sources = Vec::new();
    extend_boundary_minor_gc_root_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::Worker,
        applications.worker(),
    )?;
    extend_boundary_minor_gc_root_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
    )?;
    Ok(sources)
}

pub(crate) fn extend_boundary_minor_gc_root_writeback_write_sources(
    sources: &mut Vec<BoundaryMinorGcRootWritebackWriteSource>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
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

        let entries =
            sources
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
                })?;
        sources
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
                entries,
            })?;
        sources.push(BoundaryMinorGcRootWritebackWriteSource {
            allocation_domain,
            root_source: root_slot.source().clone(),
            replacement_tag: replacement.tag(),
            replacement_value: replacement,
            destination,
            generation,
            replacement_metadata: root_slot.value(),
        });
    }

    Ok(())
}

pub(crate) fn root_writeback_write_source_matches_binding(
    source: &BoundaryMinorGcRootWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
) -> bool {
    root_writeback_write_source_matches_binding_identity(source, binding)
        && source.replacement_tag == binding.replacement_tag()
        && source.destination == binding.destination()
        && source.generation == binding.generation()
}

pub(crate) fn root_writeback_write_source_matches_binding_identity(
    source: &BoundaryMinorGcRootWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
) -> bool {
    source.allocation_domain == binding.allocation_domain()
        && source.root_source == *binding.root_source()
}

pub(crate) fn root_writeback_write_matches_binding(
    write: &EvalGcStressBoundaryMinorGcRootWritebackWrite,
    binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
) -> bool {
    write.allocation_domain() == binding.allocation_domain()
        && write.root_source() == binding.root_source()
        && write.replacement_tag() == binding.replacement_tag()
        && write.destination() == binding.destination()
        && write.generation() == binding.generation()
}

pub(crate) fn apply_boundary_minor_gc_outcome_root_writebacks(
    outcome_value: &mut Value,
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport, EvalHeapError> {
    let value_stack_roots = validate_boundary_minor_gc_outcome_root_writeback_source_destinations(
        outcome_value,
        heap,
        plan,
    )?;
    let mut replacement = None;

    for write in plan.writes() {
        let next = write.replacement_value();
        heap.validate_collector_poll_minor_gc_object_body_binding(
            write.request(),
            write.replacement_tag(),
        )?;
        replacement = Some(next);
    }

    if let Some(next) = replacement {
        *outcome_value = next;
    }

    Ok(EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport::new(
        value_stack_roots,
    ))
}

pub(crate) fn apply_boundary_minor_gc_live_outcome_root_writebacks(
    outcome_value: &mut Value,
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport, EvalHeapError> {
    validate_boundary_minor_gc_outcome_root_writeback_source_values(outcome_value, heap, plan)?;
    let object_body_plan = boundary_minor_gc_outcome_root_object_body_write_plan(plan)?;
    let object_body_and_generation_write_report =
        heap.apply_collector_poll_minor_gc_object_body_and_generation_writes(&object_body_plan)?;
    let outcome_root_writeback_report =
        apply_boundary_minor_gc_outcome_root_writebacks(outcome_value, heap, plan)?;

    Ok(
        EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport::new(
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
        ),
    )
}

pub(crate) fn apply_boundary_minor_gc_live_reference_writebacks(
    outcome_value: &mut Value,
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    root_plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport, EvalHeapError> {
    let value_stack_roots = validate_boundary_minor_gc_outcome_root_writeback_source_values(
        outcome_value,
        heap,
        root_plan,
    )?;
    let (copied_writes, direct_writes) =
        boundary_minor_gc_heap_field_writeback_writes(heap_field_plan)?;
    let object_body_plan =
        boundary_minor_gc_reference_writeback_object_body_write_plan(root_plan, heap_field_plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        heap_field_plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        heap_field_plan.report().fields()
    );
    let outcome_root_writeback_report =
        commit_boundary_minor_gc_outcome_root_writebacks_prevalidated(
            outcome_value,
            root_plan,
            value_stack_roots,
        );

    Ok(
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport::new(
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
            heap_field_plan.report(),
        ),
    )
}

pub(crate) fn validate_boundary_minor_gc_live_reference_writebacks(
    outcome_value: &Value,
    heap: &EvalHeap,
    remembered_set: &RememberedSet,
    card_table: &GcCardTable,
    root_plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport, EvalHeapError> {
    let _ = validate_boundary_minor_gc_outcome_root_writeback_source_values(
        outcome_value,
        heap,
        root_plan,
    )?;
    let (copied_writes, direct_writes) =
        boundary_minor_gc_heap_field_writeback_writes(heap_field_plan)?;
    let object_body_plan =
        boundary_minor_gc_reference_writeback_object_body_write_plan(root_plan, heap_field_plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        heap_field_plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        heap_field_plan.report().fields()
    );

    Ok(
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport::new(
            object_body_and_generation_write_report,
            root_plan.report(),
            heap_field_plan.report(),
        ),
    )
}

pub(crate) fn validate_boundary_minor_gc_existing_destination_commit_published_remembered_edges(
    remembered_set: &RememberedSet,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<(), EvalHeapError> {
    for binding in live_bindings.heap_field_writeback_bindings() {
        if binding.writeback_object_request().is_some()
            || binding.replacement_generation() != HeapGeneration::Young
        {
            continue;
        }

        let expected_edge = RememberedEdge::new(
            binding.writeback_object(),
            binding.replacement_destination(),
        );
        if !remembered_set.edges().contains(&expected_edge) {
            return Err(
                EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingRememberedEdge {
                    source_address: expected_edge.source(),
                    target_address: expected_edge.target(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_boundary_minor_gc_existing_destination_commit_published_remembered_set(
    remembered_set: &RememberedSet,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<(), EvalHeapError> {
    let Some(expected_remembered_set) = live_bindings.expected_remembered_set() else {
        if live_bindings.install_report().bindings() == 0 {
            return Ok(());
        }
        return Err(
            EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingRememberedSetPublication {
                bindings: live_bindings.install_report().bindings(),
            },
        );
    };

    if remembered_set != expected_remembered_set {
        return Err(
            EvalHeapError::BoundaryMinorGcExistingDestinationCommitRememberedSetPublicationMismatch {
                expected_epoch: expected_remembered_set.epoch(),
                actual_epoch: remembered_set.epoch(),
                expected_edges: expected_remembered_set.len(),
                actual_edges: remembered_set.len(),
            },
        );
    }

    validate_boundary_minor_gc_existing_destination_commit_published_remembered_edges(
        remembered_set,
        live_bindings,
    )
}

pub(crate) fn validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<(), EvalHeapError> {
    for write in heap_field_plan.writes() {
        if write.writeback_object_request().is_some() {
            continue;
        }
        if object_body_plan
            .requests()
            .iter()
            .any(|request| request.destination() == write.writeback_object())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveReferenceWritebackDestinationAliasesDirectWriteback {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    destination: write.writeback_object(),
                },
            );
        }
    }

    Ok(())
}

pub(crate) fn apply_boundary_minor_gc_heap_field_writebacks(
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
    let (copied_writes, direct_writes) = boundary_minor_gc_heap_field_writeback_writes(plan)?;
    apply_boundary_minor_gc_heap_field_writebacks_from_writes(
        heap,
        remembered_set,
        card_table,
        plan.report(),
        &copied_writes,
        &direct_writes,
    )
}

pub(crate) fn apply_boundary_minor_gc_live_heap_field_writebacks(
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport, EvalHeapError> {
    let (copied_writes, direct_writes) = boundary_minor_gc_heap_field_writeback_writes(plan)?;
    let object_body_plan = boundary_minor_gc_heap_field_writeback_object_body_write_plan(plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        plan.report().fields()
    );

    Ok(
        EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport::new(
            object_body_and_generation_write_report,
            plan.report(),
        ),
    )
}

pub(crate) fn validate_boundary_minor_gc_live_heap_field_writebacks(
    heap: &EvalHeap,
    remembered_set: &RememberedSet,
    card_table: &GcCardTable,
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport, EvalHeapError> {
    let (copied_writes, direct_writes) = boundary_minor_gc_heap_field_writeback_writes(plan)?;
    let object_body_plan = boundary_minor_gc_heap_field_writeback_object_body_write_plan(plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        plan.report().fields()
    );

    Ok(
        EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport::new(
            object_body_and_generation_write_report,
            plan.report(),
        ),
    )
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_writes(
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<
    (
        Vec<AllocationCollectorPollCopiedHeapFieldWrite>,
        Vec<AllocationCollectorPollDirectHeapFieldWrite>,
    ),
    EvalHeapError,
> {
    let mut copied_writes = Vec::new();
    copied_writes
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;
    let mut direct_writes = Vec::new();
    direct_writes
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;

    for write in plan.writes() {
        if let Some(writeback_object_request) = write.writeback_object_request() {
            copied_writes.push(AllocationCollectorPollCopiedHeapFieldWrite::new(
                write.allocation_domain(),
                write.validation_object(),
                write.writeback_object(),
                write.field_index(),
                write.source().clone(),
                write.replacement_metadata(),
                write.replacement_request(),
                writeback_object_request,
            ));
        } else {
            direct_writes.push(AllocationCollectorPollDirectHeapFieldWrite::new(
                write.allocation_domain(),
                write.writeback_object(),
                write.field_index(),
                write.source().clone(),
                write.replacement_metadata(),
                write.replacement_request(),
            ));
        };
    }

    Ok((copied_writes, direct_writes))
}

pub(crate) fn apply_boundary_minor_gc_heap_field_writebacks_from_writes(
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            copied_writes,
            direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        report.fields()
    );
    Ok(report)
}

pub(crate) fn commit_boundary_minor_gc_outcome_root_writebacks_prevalidated(
    outcome_value: &mut Value,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    value_stack_roots: usize,
) -> EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
    let mut replacement = None;
    for write in plan.writes() {
        replacement = Some(write.replacement_value());
    }
    if let Some(next) = replacement {
        *outcome_value = next;
    }

    EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport::new(value_stack_roots)
}

pub(crate) fn validate_boundary_minor_gc_outcome_root_writeback_source_destinations(
    outcome_value: &Value,
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<usize, EvalHeapError> {
    let value_stack_roots =
        validate_boundary_minor_gc_outcome_root_writeback_source_values(outcome_value, heap, plan)?;
    for write in plan.writes() {
        let destination_generation = heap.generation(write.replacement_value())?;
        if destination_generation != write.generation() {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackDestinationGenerationMismatch {
                    root_source: write.root_source().clone(),
                    destination: write.destination(),
                    expected: write.generation(),
                    actual: destination_generation,
                },
            );
        }
    }

    Ok(value_stack_roots)
}

pub(crate) fn validate_boundary_minor_gc_outcome_root_writeback_source_values(
    outcome_value: &Value,
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<usize, EvalHeapError> {
    let value_stack_roots = validate_boundary_minor_gc_outcome_root_writeback_sources(plan)?;
    for write in plan.writes() {
        let expected =
            boundary_minor_gc_heap_value(write.replacement_tag(), write.request().source())?;
        if !outcome_value.raw_eq(expected) {
            return Err(EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                index: 0,
                expected_tag: expected.tag(),
                expected_payload: expected.payload_bits(),
                actual_tag: outcome_value.tag(),
                actual_payload: outcome_value.payload_bits(),
            });
        }

        let source_generation = heap.generation(expected)?;
        if source_generation != HeapGeneration::Young {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackSourceGenerationMismatch {
                    root_source: write.root_source().clone(),
                    source_address: write.request().source(),
                    expected: HeapGeneration::Young,
                    actual: source_generation,
                },
            );
        }
    }

    Ok(value_stack_roots)
}

pub(crate) fn validate_boundary_minor_gc_outcome_root_writeback_sources(
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<usize, EvalHeapError> {
    let mut value_stack_zero_seen = false;
    let mut value_stack_roots = 0usize;

    for (index, write) in plan.writes().iter().enumerate() {
        let EvalRootSource::ValueStack { slot: 0 } = write.root_source() else {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackUnsupportedSource {
                    root_source: write.root_source().clone(),
                },
            );
        };
        if value_stack_zero_seen {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackDuplicateValueStackRoot {
                    index,
                    root_source: write.root_source().clone(),
                },
            );
        }

        value_stack_zero_seen = true;
        value_stack_roots = value_stack_roots.saturating_add(1);
    }

    Ok(value_stack_roots)
}

pub(crate) fn boundary_minor_gc_outcome_root_object_body_write_plan(
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;
    requests.extend(plan.writes().iter().map(|write| write.request()));
    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_object_body_write_plan(
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let entries =
        plan.writes()
            .len()
            .checked_mul(2)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            })?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries,
        })?;

    for write in plan.writes() {
        if let Some(writeback_object_request) = write.writeback_object_request() {
            push_unique_boundary_minor_gc_object_copy_request(
                &mut requests,
                writeback_object_request,
            );
        }
        push_unique_boundary_minor_gc_object_copy_request(
            &mut requests,
            write.replacement_request(),
        );
    }

    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

pub(crate) fn boundary_minor_gc_reference_writeback_object_body_write_plan(
    root_plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let heap_field_entries = heap_field_plan.writes().len().checked_mul(2).ok_or(
        EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE,
        },
    )?;
    let entries = root_plan
        .writes()
        .len()
        .checked_add(heap_field_entries)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE,
        })?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE,
            entries,
        })?;

    for write in root_plan.writes() {
        push_unique_boundary_minor_gc_object_copy_request(&mut requests, write.request());
    }
    for write in heap_field_plan.writes() {
        if let Some(writeback_object_request) = write.writeback_object_request() {
            push_unique_boundary_minor_gc_object_copy_request(
                &mut requests,
                writeback_object_request,
            );
        }
        push_unique_boundary_minor_gc_object_copy_request(
            &mut requests,
            write.replacement_request(),
        );
    }

    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

pub(crate) fn push_unique_boundary_minor_gc_object_copy_request(
    requests: &mut Vec<AllocationCollectorPollObjectByteCopyRequest>,
    request: AllocationCollectorPollObjectByteCopyRequest,
) {
    if !requests.iter().any(|existing| *existing == request) {
        requests.push(request);
    }
}

pub(crate) fn boundary_minor_gc_heap_value(
    tag: ValueTag,
    address: GcHeapAddress,
) -> Result<Value, EvalHeapError> {
    let ptr = NonNull::new(address.address_bits() as *mut HeapObject).ok_or(
        EvalHeapError::Value(crate::value::ValueError::NullHeapPointer { tag }),
    )?;
    Value::heap(tag, ptr).map_err(EvalHeapError::Value)
}
