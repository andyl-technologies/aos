//! impl EvalHeap: object generation/body write staging and commits, and
//! copied heap-field write planning and staging.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

impl EvalHeap {
    /// Applies heap-record generation writes for relocated destinations.
    ///
    /// Each source must still be a current young survivor, and each destination
    /// address must already belong to a heap record in this evaluator side
    /// table. The full plan is validated before any record generation is
    /// changed, so an unknown source or destination leaves all records
    /// unchanged. This only writes generation metadata on existing heap records;
    /// it does not allocate destination records, bind object bytes to heap
    /// storage, rewrite references, install forwarding headers, publish
    /// remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if planned scratch storage cannot be reserved,
    /// if a source is unknown or no longer young, or if a destination address
    /// does not belong to this heap.
    pub fn apply_collector_poll_minor_gc_object_generation_writes(
        &mut self,
        plan: &AllocationCollectorPollObjectGenerationWritePlan,
    ) -> Result<AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError> {
        let planned = self.stage_collector_poll_minor_gc_object_generation_writes(plan)?;
        let report = plan.report();
        self.commit_collector_poll_minor_gc_object_generation_writes(planned);
        Ok(report)
    }

    pub(super) fn stage_collector_poll_minor_gc_object_generation_writes(
        &self,
        plan: &AllocationCollectorPollObjectGenerationWritePlan,
    ) -> Result<Vec<(usize, HeapGeneration)>, EvalHeapError> {
        let mut planned = Vec::new();
        planned
            .try_reserve_exact(plan.writes().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
                entries: plan.writes().len(),
            })?;

        for write in plan.writes().iter().copied() {
            let _ = self.record_index_for_minor_gc_survivor(write.source())?;
            let Some(destination_index) = self
                .records
                .index_of_address(write.destination().address_bits())
            else {
                return Err(
                    EvalHeapError::UnknownCollectorPollObjectGenerationDestination {
                        destination: write.destination(),
                    },
                );
            };
            planned.push((destination_index, write.generation()));
        }

        Ok(planned)
    }

    pub(super) fn commit_collector_poll_minor_gc_object_generation_writes(
        &mut self,
        planned: Vec<(usize, HeapGeneration)>,
    ) {
        for (destination_index, generation) in planned {
            self.records[destination_index].generation = generation;
        }
    }

    /// Applies heap-record object-body writes for relocated destinations.
    ///
    /// The object-copy plan must also satisfy the same global invariants as a
    /// heap-record generation write plan: destination generation must agree with
    /// survivor action, sources and destinations must be unique, destinations must
    /// not be sources, and destinations must not overlap another survivor source.
    /// Each source must still be a current young survivor with the layout captured
    /// by the object-copy request, and each destination address must already
    /// belong to a heap record with the same layout. The full plan is validated
    /// before any destination body is changed, so an unknown source, unknown
    /// destination, duplicate/overlapping copy identity, or stale layout leaves all
    /// records unchanged. This writes the typed evaluator object body and
    /// body-owned cache metadata on existing heap records; it assumes callers pass
    /// unaliased collector-owned destination records because this side table does
    /// not yet model semispace ownership. It does not allocate destination records,
    /// write generation metadata, rewrite references, install forwarding headers,
    /// publish remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the object-copy plan violates generation-write
    /// identity invariants, if planned scratch storage cannot be reserved, if a
    /// source is unknown or no longer young, if a source or destination layout no
    /// longer matches the object-copy request, or if a destination address does not
    /// belong to this heap.
    pub fn apply_collector_poll_minor_gc_object_body_writes(
        &mut self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<AllocationCollectorPollObjectBodyWriteReport, EvalHeapError> {
        let (planned, report) = self.stage_collector_poll_minor_gc_object_body_writes(plan)?;
        self.commit_collector_poll_minor_gc_object_body_writes(planned);
        Ok(report)
    }

    /// Validates paired heap-record body and generation writes without mutation.
    ///
    /// This stages the same object-body and generation writes as
    /// [`Self::apply_collector_poll_minor_gc_object_body_and_generation_writes`],
    /// then drops the staged writes instead of committing them. It is intended as
    /// a commit-orchestration preflight for callers that need to prove the
    /// existing-destination heap records can accept relocated object bodies and
    /// generation metadata before starting a larger mutation sequence. It does
    /// not allocate destination records, rewrite references, install forwarding
    /// headers, publish remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::apply_collector_poll_minor_gc_object_body_and_generation_writes`].
    /// Whether this returns `Ok` or `Err`, heap-record object bodies and
    /// generation metadata are left unchanged.
    pub fn validate_collector_poll_minor_gc_object_body_and_generation_writes(
        &self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let generation_plan = plan.object_generation_write_plan()?;
        let (_body_writes, body_write_report) =
            self.stage_collector_poll_minor_gc_object_body_writes(plan)?;
        let _generation_writes =
            self.stage_collector_poll_minor_gc_object_generation_writes(&generation_plan)?;
        let generation_write_report = generation_plan.report();

        Ok(
            AllocationCollectorPollObjectBodyAndGenerationWriteReport::new(
                body_write_report,
                generation_write_report,
            ),
        )
    }

    /// Applies paired heap-record body and generation writes for relocated destinations.
    ///
    /// This validates the same invariants as
    /// [`Self::apply_collector_poll_minor_gc_object_body_writes`] and
    /// [`Self::apply_collector_poll_minor_gc_object_generation_writes`] before
    /// mutating either object bodies or generation metadata. It only applies writes
    /// to destination records that already exist in this evaluator heap side table;
    /// it does not allocate destination records, rewrite references, install
    /// forwarding headers, publish remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the object-copy plan violates generation-write
    /// identity invariants, if planned scratch storage cannot be reserved, if a
    /// source is unknown or no longer young, if a source or destination layout no
    /// longer matches the object-copy request, or if a destination address does not
    /// belong to this heap. When an error is returned, neither object bodies nor
    /// generation metadata are changed.
    pub fn apply_collector_poll_minor_gc_object_body_and_generation_writes(
        &mut self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let generation_plan = plan.object_generation_write_plan()?;
        let (body_writes, body_write_report) =
            self.stage_collector_poll_minor_gc_object_body_writes(plan)?;
        let generation_writes =
            self.stage_collector_poll_minor_gc_object_generation_writes(&generation_plan)?;
        let generation_write_report = generation_plan.report();

        self.commit_collector_poll_minor_gc_object_body_writes(body_writes);
        self.commit_collector_poll_minor_gc_object_generation_writes(generation_writes);

        Ok(
            AllocationCollectorPollObjectBodyAndGenerationWriteReport::new(
                body_write_report,
                generation_write_report,
            ),
        )
    }

    pub(super) fn stage_collector_poll_minor_gc_object_body_writes(
        &self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<
        (
            Vec<CollectorPollObjectBodyWrite>,
            AllocationCollectorPollObjectBodyWriteReport,
        ),
        EvalHeapError,
    > {
        let _ = plan.object_generation_write_plan()?;
        let mut planned = Vec::new();
        planned
            .try_reserve_exact(plan.requests().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_BODY_WRITES_TABLE,
                entries: plan.requests().len(),
            })?;

        let mut report = AllocationCollectorPollObjectBodyWriteReport::default();
        for request in plan.requests().iter().copied() {
            let source_index = self.record_index_for_minor_gc_survivor(request.source())?;
            validate_object_byte_copy_request_source_record_layout(
                request,
                &self.records[source_index],
            )?;
            let Some(destination_index) = self
                .records
                .index_of_address(request.destination().address_bits())
            else {
                return Err(EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                    destination: request.destination(),
                });
            };
            validate_object_body_write_destination_record_layout(
                request,
                &self.records[destination_index],
            )?;

            let source = &self.records[source_index];
            let source_address = source.ptr.as_ptr() as usize;
            planned.push(CollectorPollObjectBodyWrite {
                destination_index,
                object: source.object.clone(),
                layout: source.layout,
                structural_hash: source.structural_hash,
                value_hash: self.records.cold_value_hash(source_address),
                captured_value_hash: self.records.cold_captured_value_hash(source_address),
            });
            report.record(request);
        }

        Ok((planned, report))
    }

    pub(super) fn commit_collector_poll_minor_gc_object_body_writes(
        &mut self,
        planned: Vec<CollectorPollObjectBodyWrite>,
    ) {
        for write in planned {
            let address = self.records[write.destination_index].ptr.as_ptr() as usize;
            let destination = &mut self.records[write.destination_index];
            destination.object = write.object;
            destination.layout = write.layout;
            destination.structural_hash = write.structural_hash;
            self.records.set_cold_value_hash(address, write.value_hash);
            self.records
                .set_cold_captured_value_hash(address, write.captured_value_hash);
        }
    }

    /// Creates object-copy metadata for existing test heap records.
    ///
    /// The request uses the source record's current layout and the destination
    /// implied by `action`, so tests can exercise object-body writers without
    /// reaching into heap record internals.
    #[cfg(test)]
    pub(crate) fn collector_poll_minor_gc_object_byte_copy_request_for_test(
        &self,
        source: Value,
        destination: Value,
        action: MinorGcSurvivorAction,
    ) -> Result<AllocationCollectorPollObjectByteCopyRequest, EvalHeapError> {
        let source_record = self.record_for_scannable_value(source)?;
        let destination_record = self.record_for_scannable_value(destination)?;
        Ok(AllocationCollectorPollObjectByteCopyRequest::for_test(
            gc_address_for_record(source_record)?,
            gc_address_for_record(destination_record)?,
            action,
            generation_for_destination_action(action),
            source_record.layout.size_bytes,
            source_record.layout.align,
        ))
    }

    /// Validates that a relocated destination heap record has a bound object body.
    ///
    /// The source must still be a young survivor, source and destination layouts
    /// must match the object-copy request, both records must carry `tag`, and the
    /// destination body must be representation-equivalent to the source body. This
    /// is the side-table body binding check used by narrow live-root writeback
    /// applicators after [`Self::apply_collector_poll_minor_gc_object_body_writes`]
    /// has installed destination bodies.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if either heap record is missing, if the source is
    /// no longer young, if either layout is stale, if a record tag disagrees with
    /// `tag`, or if the destination object body does not match the source body.
    pub fn validate_collector_poll_minor_gc_object_body_binding(
        &self,
        request: AllocationCollectorPollObjectByteCopyRequest,
        tag: ValueTag,
    ) -> Result<(), EvalHeapError> {
        let source_index = self.record_index_for_minor_gc_survivor(request.source())?;
        let source = &self.records[source_index];
        validate_object_byte_copy_request_source_record_layout(request, source)?;
        if source.object.tag() != tag {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: request.source(),
                destination: request.destination(),
                reason: "source record tag does not match root writeback tag",
            });
        }

        let Some(destination) = self
            .records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == request.destination().address_bits())
        else {
            return Err(EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: request.destination(),
            });
        };
        validate_object_body_write_destination_record_layout(request, destination)?;
        if destination.object.tag() != tag {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: request.source(),
                destination: request.destination(),
                reason: "destination record tag does not match root writeback tag",
            });
        }
        if !heap_object_value_raw_eq(&source.object, &destination.object) {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: request.source(),
                destination: request.destination(),
                reason: "destination record body does not match source record body",
            });
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn apply_collector_poll_minor_gc_copied_heap_field_writes(
        &mut self,
        writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    ) -> Result<AllocationCollectorPollCopiedHeapFieldWriteReport, EvalHeapError> {
        let (planned, report) =
            self.plan_collector_poll_minor_gc_copied_heap_field_writes(writes)?;
        let (staged, staged_environment) =
            self.stage_collector_poll_minor_gc_copied_heap_field_writes(&planned)?;
        let staged_structural = self.stage_structural_writebacks(&staged, &[], &[])?;
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged);
        staged_environment.commit();
        self.commit_structural_writebacks(staged_structural);

        Ok(report)
    }

    pub(super) fn plan_collector_poll_minor_gc_copied_heap_field_writes(
        &self,
        writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    ) -> Result<
        (
            Vec<CollectorPollCopiedHeapFieldWrite>,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_copied_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollCopiedHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| copied_heap_field_write_identity_matches(existing, write))
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
            planned.push(self.plan_collector_poll_minor_gc_copied_heap_field_write(write)?);
            report.record();
        }

        Ok((planned, report))
    }

    pub(super) fn plan_collector_poll_minor_gc_copied_heap_field_write(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<CollectorPollCopiedHeapFieldWrite, EvalHeapError> {
        self.validate_copied_heap_field_write_requests(write)?;

        let writeback_request = write.writeback_object_request();
        let writeback_tag = self.object_body_binding_tag(writeback_request)?;
        self.validate_collector_poll_minor_gc_object_body_binding(
            writeback_request,
            writeback_tag,
        )?;
        self.validate_copied_heap_field_writeback_generation(write)?;

        let record_index = self.record_index_for_reference_slot_object(write.writeback_object())?;
        let record = &self.records[record_index];
        let edges = self.scan_record_edges(record)?;
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
                EvalHeapError::CollectorPollCopiedHeapFieldWriteValueMismatch {
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
        self.validate_copied_heap_field_replacement_generation(write)?;
        let replacement_value =
            value_for_resolved_generation(replacement_tag, write.replacement())?;
        validate_copied_heap_field_write_object_source(&record.object, write)?;

        Ok(CollectorPollCopiedHeapFieldWrite {
            record_index,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            base_object: None,
        })
    }

    pub(super) fn plan_collector_poll_minor_gc_copied_heap_field_writes_for_live_destinations(
        &self,
        writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    ) -> Result<
        (
            Vec<CollectorPollCopiedHeapFieldWrite>,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_copied_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollCopiedHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| copied_heap_field_write_identity_matches(existing, write))
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
                self.plan_collector_poll_minor_gc_copied_heap_field_write_for_live_destination(
                    write,
                )?,
            );
            report.record();
        }

        Ok((planned, report))
    }

    pub(super) fn plan_collector_poll_minor_gc_copied_heap_field_write_for_live_destination(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<CollectorPollCopiedHeapFieldWrite, EvalHeapError> {
        self.validate_copied_heap_field_write_requests(write)?;

        let destination_index =
            self.record_index_for_reference_slot_object(write.writeback_object())?;
        let validation_index =
            self.record_index_for_reference_slot_object(write.validation_object())?;
        let record = &self.records[validation_index];
        let edges = self.scan_record_edges(record)?;
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
                EvalHeapError::CollectorPollCopiedHeapFieldWriteValueMismatch {
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
        validate_copied_heap_field_write_object_source(&record.object, write)?;

        Ok(CollectorPollCopiedHeapFieldWrite {
            record_index: destination_index,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            base_object: Some(record.object.clone()),
        })
    }

    #[cfg(test)]
    pub(super) fn stage_collector_poll_minor_gc_copied_heap_field_writes(
        &self,
        writes: &[CollectorPollCopiedHeapFieldWrite],
    ) -> Result<(Vec<(usize, HeapObjectValue)>, EnvironmentWritebackStage), EvalHeapError> {
        let mut staged: Vec<(usize, HeapObjectValue)> = Vec::new();
        staged.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;
        let mut staged_environment =
            EnvironmentWritebackStage::try_new(writes.len()).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                    entries: writes.len(),
                }
            })?;

        self.stage_collector_poll_minor_gc_copied_heap_field_writes_into(
            writes,
            &mut staged,
            &mut staged_environment,
            writes.len(),
        )?;

        Ok((staged, staged_environment))
    }

    pub(super) fn stage_collector_poll_minor_gc_copied_heap_field_writes_into(
        &self,
        writes: &[CollectorPollCopiedHeapFieldWrite],
        staged: &mut Vec<(usize, HeapObjectValue)>,
        staged_environment: &mut EnvironmentWritebackStage,
        entries: usize,
    ) -> Result<(), EvalHeapError> {
        for write in writes {
            let object = self
                .staged_collector_poll_minor_gc_heap_field_write_object_mut_with_base(
                    staged,
                    write.record_index,
                    write.base_object.as_ref(),
                    MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                    entries,
                )?;
            stage_record_owned_heap_field_write(
                object,
                &write.source,
                write.replacement,
                staged_environment,
            )
            .map_err(|error| copied_heap_field_write_object_error(write, error))?;
        }

        Ok(())
    }

    pub(super) fn validate_copied_heap_field_write_requests(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let writeback_request = write.writeback_object_request();
        if writeback_request.source() != write.validation_object() {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestSourceMismatch {
                    allocation_domain: write.allocation_domain(),
                    validation_object: write.validation_object(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    actual_source: writeback_request.source(),
                },
            );
        }
        if writeback_request.destination() != write.writeback_object() {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestDestinationMismatch {
                    allocation_domain: write.allocation_domain(),
                    validation_object: write.validation_object(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    request_destination: writeback_request.destination(),
                },
            );
        }
        let _ = validate_object_byte_copy_request_destination_generation(writeback_request)?;

        let replacement_request = write.replacement_request();
        let ResolvedValueGeneration::Heap {
            address: replacement,
            generation,
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
        if replacement_request.destination() != replacement {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteReplacementRequestDestinationMismatch {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    binding_replacement: replacement,
                    request_destination: replacement_request.destination(),
                },
            );
        }
        let expected_generation =
            validate_object_byte_copy_request_destination_generation(replacement_request)?;
        if generation != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    expected: expected_generation,
                    actual: generation,
                    action: replacement_request.action(),
                },
            );
        }
        Ok(())
    }
}
