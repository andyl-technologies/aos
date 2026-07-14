//! impl EvalHeap: copied/direct heap-field write validation and
//! application, and direct heap-field write planning.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

impl EvalHeap {
    pub(super) fn validate_copied_heap_field_writeback_generation(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let expected = write.writeback_object_request().destination_generation();
        let actual =
            self.generation_for_address(write.writeback_object(), "heap-field writeback object")?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollCopiedHeapFieldWriteObjectGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    expected,
                    actual,
                },
            );
        }
        Ok(())
    }

    pub(super) fn validate_copied_heap_field_replacement_generation(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let ResolvedValueGeneration::Heap {
            address: replacement,
            generation: expected,
        } = write.replacement()
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    value: write.replacement(),
                },
            );
        };
        let actual = self.generation_for_address(replacement, "heap-field replacement")?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollCopiedHeapFieldWriteReplacementGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    expected,
                    actual,
                },
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn apply_collector_poll_minor_gc_direct_heap_field_writes(
        &mut self,
        writes: &[AllocationCollectorPollDirectHeapFieldWrite],
    ) -> Result<AllocationCollectorPollDirectHeapFieldWriteReport, EvalHeapError> {
        let (planned, report) =
            self.plan_collector_poll_minor_gc_direct_heap_field_writes(writes, false)?;
        let (staged, staged_flat_lists, staged_flat_attrs, staged_environment, staged_structural) =
            self.stage_collector_poll_minor_gc_direct_heap_field_writes(&planned)?;
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged);
        self.commit_collector_poll_minor_gc_staged_flat_list_writes(staged_flat_lists);
        self.commit_collector_poll_minor_gc_staged_flat_attrs_writes(staged_flat_attrs);
        staged_environment.commit();
        self.commit_structural_writebacks(staged_structural);

        Ok(report)
    }

    #[cfg(test)]
    pub(crate) fn apply_collector_poll_minor_gc_heap_field_writes(
        &mut self,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
    ) -> Result<
        (
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        self.apply_collector_poll_minor_gc_heap_field_writes_with_optional_barriers(
            copied_writes,
            direct_writes,
            None,
        )
    }

    pub(crate) fn apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
        &mut self,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> Result<
        (
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        self.apply_collector_poll_minor_gc_heap_field_writes_with_optional_barriers(
            copied_writes,
            direct_writes,
            Some((remembered_set, card_table)),
        )
    }

    pub(crate) fn apply_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
        &mut self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> Result<
        (
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        let staged = self.stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            object_body_plan,
            copied_writes,
            direct_writes,
            remembered_set,
            card_table,
        )?;
        Ok(
            self.commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
                staged,
                remembered_set,
                card_table,
            ),
        )
    }

    pub(crate) fn validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
        &self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &RememberedSet,
        card_table: &GcCardTable,
    ) -> Result<
        (
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        let staged = self.stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            object_body_plan,
            copied_writes,
            direct_writes,
            remembered_set,
            card_table,
        )?;

        Ok((
            staged.object_body_and_generation_write_report(),
            staged.copied_report(),
            staged.direct_report(),
        ))
    }

    /// Stages live object, field, remembered-set, and card-table writes.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if object-body, generation, field, or barrier
    /// staging fails. The evaluator heap and supplied side tables are left
    /// unchanged when an error is returned.
    pub(crate) fn stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
        &self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &RememberedSet,
        card_table: &GcCardTable,
    ) -> Result<AllocationCollectorPollLiveHeapFieldWriteStage, EvalHeapError> {
        validate_collector_poll_minor_gc_heap_field_write_request_invariants(
            copied_writes,
            direct_writes,
        )?;
        let generation_plan = object_body_plan.object_generation_write_plan()?;
        let (object_body_writes, body_write_report) =
            self.stage_collector_poll_minor_gc_object_body_writes(object_body_plan)?;
        let object_generation_writes =
            self.stage_collector_poll_minor_gc_object_generation_writes(&generation_plan)?;
        let generation_write_report = generation_plan.report();
        let (planned_copied, copied_report) = self
            .plan_collector_poll_minor_gc_copied_heap_field_writes_for_live_destinations(
                copied_writes,
            )?;
        let (planned_direct, direct_report) = self
            .plan_collector_poll_minor_gc_direct_heap_field_writes_for_live_destinations(
                direct_writes,
                true,
            )?;
        let entries = copied_writes.len().checked_add(direct_writes.len()).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            },
        )?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(entries)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            })?;
        let mut staged_flat_lists: Vec<(NonNull<HeapObject>, NixList)> = Vec::new();
        let mut staged_flat_attrs: Vec<(NonNull<HeapObject>, FlatAttrs)> = Vec::new();
        let mut staged_environment = EnvironmentWritebackStage::try_new(entries).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            }
        })?;
        self.stage_collector_poll_minor_gc_copied_heap_field_writes_into(
            &planned_copied,
            &mut staged,
            &mut staged_environment,
            entries,
        )?;
        self.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &planned_direct,
            &mut staged,
            &mut staged_flat_lists,
            &mut staged_flat_attrs,
            &mut staged_environment,
            entries,
        )?;
        let staged_structural_writebacks =
            self.stage_structural_writebacks(&staged, &staged_flat_lists, &staged_flat_attrs)?;
        let staged_barriers = self.stage_collector_poll_minor_gc_direct_heap_field_write_barriers(
            &planned_direct,
            remembered_set,
            card_table,
        )?;

        Ok(AllocationCollectorPollLiveHeapFieldWriteStage {
            object_body_writes,
            object_generation_writes,
            staged_heap_field_writes: staged,
            staged_flat_list_writes: staged_flat_lists,
            staged_flat_attrs_writes: staged_flat_attrs,
            staged_environment_writes: staged_environment,
            staged_structural_writebacks,
            staged_barriers,
            object_body_and_generation_write_report:
                AllocationCollectorPollObjectBodyAndGenerationWriteReport::new(
                    body_write_report,
                    generation_write_report,
                ),
            copied_report,
            direct_report,
        })
    }

    /// Commits prevalidated live heap-field writes and staged side-table changes.
    pub(crate) fn commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
        &mut self,
        staged: AllocationCollectorPollLiveHeapFieldWriteStage,
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> (
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        AllocationCollectorPollCopiedHeapFieldWriteReport,
        AllocationCollectorPollDirectHeapFieldWriteReport,
    ) {
        let AllocationCollectorPollLiveHeapFieldWriteStage {
            object_body_writes,
            object_generation_writes,
            staged_heap_field_writes,
            staged_flat_list_writes,
            staged_flat_attrs_writes,
            staged_environment_writes,
            staged_structural_writebacks,
            staged_barriers,
            object_body_and_generation_write_report,
            copied_report,
            direct_report,
        } = staged;

        self.commit_collector_poll_minor_gc_object_body_writes(object_body_writes);
        self.commit_collector_poll_minor_gc_object_generation_writes(object_generation_writes);
        if let Some((staged_remembered_set, staged_card_table)) = staged_barriers {
            *remembered_set = staged_remembered_set;
            *card_table = staged_card_table;
        }
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged_heap_field_writes);
        self.commit_collector_poll_minor_gc_staged_flat_list_writes(staged_flat_list_writes);
        self.commit_collector_poll_minor_gc_staged_flat_attrs_writes(staged_flat_attrs_writes);
        staged_environment_writes.commit();
        self.commit_structural_writebacks(staged_structural_writebacks);

        (
            object_body_and_generation_write_report,
            copied_report,
            direct_report,
        )
    }

    pub(super) fn apply_collector_poll_minor_gc_heap_field_writes_with_optional_barriers(
        &mut self,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        barrier_targets: Option<(&mut RememberedSet, &mut GcCardTable)>,
    ) -> Result<
        (
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_heap_field_write_request_invariants(
            copied_writes,
            direct_writes,
        )?;
        let allow_young_direct_replacements = barrier_targets.is_some();
        let (planned_copied, copied_report) =
            self.plan_collector_poll_minor_gc_copied_heap_field_writes(copied_writes)?;
        let (planned_direct, direct_report) = self
            .plan_collector_poll_minor_gc_direct_heap_field_writes(
                direct_writes,
                allow_young_direct_replacements,
            )?;

        let entries = copied_writes.len().checked_add(direct_writes.len()).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            },
        )?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(entries)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            })?;
        let mut staged_flat_lists: Vec<(NonNull<HeapObject>, NixList)> = Vec::new();
        let mut staged_flat_attrs: Vec<(NonNull<HeapObject>, FlatAttrs)> = Vec::new();
        let mut staged_environment = EnvironmentWritebackStage::try_new(entries).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            }
        })?;
        self.stage_collector_poll_minor_gc_copied_heap_field_writes_into(
            &planned_copied,
            &mut staged,
            &mut staged_environment,
            entries,
        )?;
        self.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &planned_direct,
            &mut staged,
            &mut staged_flat_lists,
            &mut staged_flat_attrs,
            &mut staged_environment,
            entries,
        )?;
        let staged_structural =
            self.stage_structural_writebacks(&staged, &staged_flat_lists, &staged_flat_attrs)?;

        if let Some((remembered_set, card_table)) = barrier_targets {
            self.record_collector_poll_minor_gc_direct_heap_field_write_barriers(
                &planned_direct,
                remembered_set,
                card_table,
            )?;
        }
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged);
        self.commit_collector_poll_minor_gc_staged_flat_list_writes(staged_flat_lists);
        self.commit_collector_poll_minor_gc_staged_flat_attrs_writes(staged_flat_attrs);
        staged_environment.commit();
        self.commit_structural_writebacks(staged_structural);

        Ok((copied_report, direct_report))
    }

    pub(super) fn plan_collector_poll_minor_gc_direct_heap_field_writes(
        &self,
        writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        allow_young_replacements: bool,
    ) -> Result<
        (
            Vec<CollectorPollDirectHeapFieldWrite>,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_direct_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollDirectHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| direct_heap_field_write_identity_matches(existing, write))
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                        index,
                        allocation_domain: write.allocation_domain(),
                        writeback_object: write.writeback_object(),
                        field_index: write.field_index(),
                        field_source: write.source().clone(),
                    },
                );
            }
            planned.push(self.plan_collector_poll_minor_gc_direct_heap_field_write(
                write,
                allow_young_replacements,
            )?);
            report.record();
        }

        Ok((planned, report))
    }

    pub(super) fn plan_collector_poll_minor_gc_direct_heap_field_write(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        allow_young_replacements: bool,
    ) -> Result<CollectorPollDirectHeapFieldWrite, EvalHeapError> {
        self.validate_direct_heap_field_write_requests(write, allow_young_replacements)?;

        let target =
            self.heap_field_write_target_for_reference_slot_object(write.writeback_object())?;
        let edges = match target {
            HeapFieldWriteTarget::Record(record_index) => {
                let record = &self.records[record_index];
                self.validate_direct_heap_field_writeback_generation(write, record)?;
                self.scan_record_edges(record)?
            }
            HeapFieldWriteTarget::FlatList(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?
            }
        };
        let Some(edge) = edges.get(write.field_index()) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: None,
            });
        };
        if edge.source() != write.source() {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: Some(edge.source().clone()),
            });
        }

        let expected = ResolvedValueGeneration::Heap {
            address: write.replacement_request().source(),
            generation: HeapGeneration::Young,
        };
        let actual = self.resolved_generation_for_value(edge.value())?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    expected,
                    actual,
                },
            );
        }

        let replacement_tag = edge.value().tag();
        self.validate_collector_poll_minor_gc_object_body_binding(
            write.replacement_request(),
            replacement_tag,
        )?;
        self.validate_direct_heap_field_replacement_generation(write)?;
        let replacement_value =
            value_for_resolved_generation(replacement_tag, write.replacement())?;
        match target {
            HeapFieldWriteTarget::Record(record_index) => {
                validate_direct_heap_field_write_object_source(
                    &self.records[record_index].object,
                    write,
                )?;
            }
            HeapFieldWriteTarget::FlatList(_) => {
                validate_flat_list_direct_heap_field_write_source(write)?;
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                validate_flat_attrs_direct_heap_field_write_source(
                    self.flat_attrs_payload(ptr)?,
                    write,
                )?;
            }
        }
        let remembered_edge = match write.replacement() {
            ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } => Some(RememberedEdge::new(write.writeback_object(), target)),
            ResolvedValueGeneration::Inline | ResolvedValueGeneration::Heap { .. } => None,
        };

        Ok(CollectorPollDirectHeapFieldWrite {
            target,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            remembered_edge,
        })
    }

    /// Resolves a direct heap-field writeback object to its staged target.
    pub(super) fn heap_field_write_target_for_reference_slot_object(
        &self,
        address: GcHeapAddress,
    ) -> Result<HeapFieldWriteTarget, EvalHeapError> {
        if let Some(index) = self.records.index_of_address(address.address_bits()) {
            return Ok(HeapFieldWriteTarget::Record(index));
        }
        if let Some(ptr) = NonNull::new(address.address_bits() as *mut HeapObject) {
            if self.flat_lists.kind_of(ptr).is_some() {
                return Ok(HeapFieldWriteTarget::FlatList(ptr));
            }
            if self.flat_attrs.kind_of(ptr).is_some() {
                return Ok(HeapFieldWriteTarget::FlatAttrs(ptr));
            }
        }
        Err(EvalHeapError::UnknownCollectorPollReferenceSlotAddress { address })
    }

    /// Generation/domain validation for a flat direct writeback target.
    ///
    /// The flat analog of `validate_direct_heap_field_writeback_generation`:
    /// flat lists and attrsets are permanent-shared by construction.
    pub(super) fn validate_flat_direct_heap_field_writeback_generation(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let expected = expected_direct_heap_field_write_generation(write.allocation_domain());
        let actual = HeapGeneration::Permanent;
        if write.allocation_domain() != HeapAllocationDomain::PermanentShared || actual != expected
        {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    expected,
                    actual,
                },
            );
        }

        Ok(())
    }

    pub(super) fn plan_collector_poll_minor_gc_direct_heap_field_writes_for_live_destinations(
        &self,
        writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        allow_young_replacements: bool,
    ) -> Result<
        (
            Vec<CollectorPollDirectHeapFieldWrite>,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_direct_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollDirectHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| direct_heap_field_write_identity_matches(existing, write))
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                        index,
                        allocation_domain: write.allocation_domain(),
                        writeback_object: write.writeback_object(),
                        field_index: write.field_index(),
                        field_source: write.source().clone(),
                    },
                );
            }
            planned.push(
                self.plan_collector_poll_minor_gc_direct_heap_field_write_for_live_destination(
                    write,
                    allow_young_replacements,
                )?,
            );
            report.record();
        }

        Ok((planned, report))
    }

    pub(super) fn plan_collector_poll_minor_gc_direct_heap_field_write_for_live_destination(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        allow_young_replacements: bool,
    ) -> Result<CollectorPollDirectHeapFieldWrite, EvalHeapError> {
        self.validate_direct_heap_field_write_requests(write, allow_young_replacements)?;

        let target =
            self.heap_field_write_target_for_reference_slot_object(write.writeback_object())?;
        let edges = match target {
            HeapFieldWriteTarget::Record(record_index) => {
                let record = &self.records[record_index];
                self.validate_direct_heap_field_writeback_generation(write, record)?;
                self.scan_record_edges(record)?
            }
            HeapFieldWriteTarget::FlatList(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?
            }
        };
        let Some(edge) = edges.get(write.field_index()) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: None,
            });
        };
        if edge.source() != write.source() {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: Some(edge.source().clone()),
            });
        }

        let expected = ResolvedValueGeneration::Heap {
            address: write.replacement_request().source(),
            generation: HeapGeneration::Young,
        };
        let actual = self.resolved_generation_for_value(edge.value())?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    expected,
                    actual,
                },
            );
        }

        let replacement_tag = edge.value().tag();
        let replacement_value =
            value_for_resolved_generation(replacement_tag, write.replacement())?;
        match target {
            HeapFieldWriteTarget::Record(record_index) => {
                validate_direct_heap_field_write_object_source(
                    &self.records[record_index].object,
                    write,
                )?;
            }
            HeapFieldWriteTarget::FlatList(_) => {
                validate_flat_list_direct_heap_field_write_source(write)?;
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                validate_flat_attrs_direct_heap_field_write_source(
                    self.flat_attrs_payload(ptr)?,
                    write,
                )?;
            }
        }
        let remembered_edge = match write.replacement() {
            ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } => Some(RememberedEdge::new(write.writeback_object(), target)),
            ResolvedValueGeneration::Inline | ResolvedValueGeneration::Heap { .. } => None,
        };

        Ok(CollectorPollDirectHeapFieldWrite {
            target,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            remembered_edge,
        })
    }
}
