//! impl EvalHeap: staged direct heap-field write doors — staging into
//! caller buffers, staged flat list/attrs write objects, commits, write
//! barriers, and the request/generation validators they enforce.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

impl EvalHeap {
    // Pre-split audience was the heap module (`pub(super)` in roots.rs).
    pub(in crate::eval::heap) fn stage_collector_poll_minor_gc_direct_heap_field_writes_into(
        &self,
        writes: &[CollectorPollDirectHeapFieldWrite],
        staged: &mut Vec<(usize, HeapObjectValue)>,
        staged_flat_lists: &mut Vec<(NonNull<HeapObject>, NixList)>,
        staged_flat_attrs: &mut Vec<(NonNull<HeapObject>, FlatAttrs)>,
        staged_environment: &mut EnvironmentWritebackStage,
        entries: usize,
    ) -> Result<(), EvalHeapError> {
        for write in writes {
            match write.target {
                HeapFieldWriteTarget::Record(record_index) => {
                    let object = self.staged_collector_poll_minor_gc_heap_field_write_object_mut(
                        staged,
                        record_index,
                        MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                        entries,
                    )?;
                    stage_record_owned_heap_field_write(
                        object,
                        &write.source,
                        write.replacement,
                        staged_environment,
                    )
                    .map_err(|error| direct_heap_field_write_object_error(write, error))?;
                }
                HeapFieldWriteTarget::FlatList(ptr) => {
                    let list = self.staged_flat_list_heap_field_write_object_mut(
                        staged_flat_lists,
                        ptr,
                        MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                        entries,
                    )?;
                    *list =
                        flat_list_heap_field_write_object(list, &write.source, write.replacement)
                            .map_err(|error| direct_heap_field_write_object_error(write, error))?;
                }
                HeapFieldWriteTarget::FlatAttrs(ptr) => {
                    let metadata = self.flat_attrs_payload(ptr)?.metadata;
                    let attrs = self.staged_flat_attrs_heap_field_write_object_mut(
                        staged_flat_attrs,
                        ptr,
                        MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                        entries,
                    )?;
                    *attrs = flat_attrs_heap_field_write_object(
                        metadata,
                        attrs,
                        &write.source,
                        write.replacement,
                    )
                    .map_err(|error| direct_heap_field_write_object_error(write, error))?;
                }
            }
        }

        Ok(())
    }

    /// Returns the staged flat-list spine for `ptr`, cloning the live payload
    /// on first touch (the flat analog of the record staging buffer).
    pub(super) fn staged_flat_list_heap_field_write_object_mut<'a>(
        &self,
        staged: &'a mut Vec<(NonNull<HeapObject>, NixList)>,
        ptr: NonNull<HeapObject>,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut NixList, EvalHeapError> {
        if let Some(index) = staged.iter().position(|(existing, _)| *existing == ptr) {
            return Ok(&mut staged[index].1);
        }

        let base = self.flat_list_payload(ptr)?.clone();
        staged.push((ptr, base));
        let Some((_, list)) = staged.last_mut() else {
            return Err(EvalHeapError::RootScanAllocationFailed { table, entries });
        };
        Ok(list)
    }

    /// Commits staged flat-list spines through the flat store's exclusive
    /// writeback door.
    ///
    /// # Panics
    ///
    /// Panics if a staged address no longer resolves as a flat list, which
    /// staging validated under the same exclusive borrow — the flat analog of
    /// the record commit's index panic on a broken commit invariant.
    pub(super) fn commit_collector_poll_minor_gc_staged_flat_list_writes(
        &mut self,
        staged: Vec<(NonNull<HeapObject>, NixList)>,
    ) {
        for (ptr, list) in staged {
            if let Err(error) = self.flat_list_commit_writeback(ptr, list) {
                unreachable!("staged flat-list writeback failed to commit: {error}");
            }
        }
    }

    /// Returns the staged flat-attrs entry storage for `ptr`, cloning the
    /// live payload's entries on first touch (the flat analog of the record
    /// staging buffer; the payload metadata is immutable and never staged).
    pub(super) fn staged_flat_attrs_heap_field_write_object_mut<'a>(
        &self,
        staged: &'a mut Vec<(NonNull<HeapObject>, FlatAttrs)>,
        ptr: NonNull<HeapObject>,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut FlatAttrs, EvalHeapError> {
        if let Some(index) = staged.iter().position(|(existing, _)| *existing == ptr) {
            return Ok(&mut staged[index].1);
        }

        let base = self.flat_attrs_payload(ptr)?.attrs.clone();
        staged.push((ptr, base));
        let Some((_, attrs)) = staged.last_mut() else {
            return Err(EvalHeapError::RootScanAllocationFailed { table, entries });
        };
        Ok(attrs)
    }

    /// Commits staged flat-attrs entry storage through the flat store's
    /// exclusive writeback door.
    ///
    /// # Panics
    ///
    /// Panics if a staged address no longer resolves as a flat attrset,
    /// which staging validated under the same exclusive borrow — the flat
    /// analog of the record commit's index panic on a broken commit
    /// invariant.
    pub(super) fn commit_collector_poll_minor_gc_staged_flat_attrs_writes(
        &mut self,
        staged: Vec<(NonNull<HeapObject>, FlatAttrs)>,
    ) {
        for (ptr, attrs) in staged {
            if let Err(error) = self.flat_attrs_commit_writeback(ptr, attrs) {
                unreachable!("staged flat-attrs writeback failed to commit: {error}");
            }
        }
    }

    pub(super) fn staged_collector_poll_minor_gc_heap_field_write_object_mut<'a>(
        &self,
        staged: &'a mut Vec<(usize, HeapObjectValue)>,
        record_index: usize,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut HeapObjectValue, EvalHeapError> {
        self.staged_collector_poll_minor_gc_heap_field_write_object_mut_with_base(
            staged,
            record_index,
            None,
            table,
            entries,
        )
    }

    pub(super) fn staged_collector_poll_minor_gc_heap_field_write_object_mut_with_base<'a>(
        &self,
        staged: &'a mut Vec<(usize, HeapObjectValue)>,
        record_index: usize,
        base_object: Option<&HeapObjectValue>,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut HeapObjectValue, EvalHeapError> {
        if let Some(index) = staged
            .iter()
            .position(|(existing, _)| *existing == record_index)
        {
            return Ok(&mut staged[index].1);
        }

        staged.push((
            record_index,
            base_object
                .cloned()
                .unwrap_or_else(|| self.records[record_index].object.clone()),
        ));
        let Some((_, object)) = staged.last_mut() else {
            return Err(EvalHeapError::RootScanAllocationFailed { table, entries });
        };
        Ok(object)
    }

    pub(super) fn commit_collector_poll_minor_gc_staged_heap_field_writes(
        &mut self,
        staged: Vec<(usize, HeapObjectValue)>,
    ) {
        for (record_index, object) in staged {
            let address = self.records[record_index].ptr.as_ptr() as usize;
            let record = &mut self.records[record_index];
            record.object = object;
            record.structural_hash = None;
            self.records.clear_cold_hashes(address);
        }
    }

    pub(super) fn record_collector_poll_minor_gc_direct_heap_field_write_barriers(
        &self,
        writes: &[CollectorPollDirectHeapFieldWrite],
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> Result<(), EvalHeapError> {
        if let Some((staged_remembered_set, staged_card_table)) = self
            .stage_collector_poll_minor_gc_direct_heap_field_write_barriers(
                writes,
                remembered_set,
                card_table,
            )?
        {
            *remembered_set = staged_remembered_set;
            *card_table = staged_card_table;
        }
        Ok(())
    }

    pub(super) fn stage_collector_poll_minor_gc_direct_heap_field_write_barriers(
        &self,
        writes: &[CollectorPollDirectHeapFieldWrite],
        remembered_set: &RememberedSet,
        card_table: &GcCardTable,
    ) -> Result<Option<(RememberedSet, GcCardTable)>, EvalHeapError> {
        if writes.iter().all(|write| write.remembered_edge.is_none()) {
            return Ok(None);
        }

        let mut staged_remembered_set =
            self.clone_remembered_set_for_direct_heap_field_write_barriers(remembered_set)?;
        let mut staged_card_table = card_table
            .try_clone()
            .map_err(EvalHeapError::GenerationalGc)?;
        for write in writes {
            let Some(edge) = write.remembered_edge else {
                continue;
            };
            staged_remembered_set
                .record(edge)
                .map_err(EvalHeapError::GenerationalGc)?;
            staged_card_table
                .mark_source(edge.source())
                .map_err(EvalHeapError::GenerationalGc)?;
        }

        Ok(Some((staged_remembered_set, staged_card_table)))
    }

    pub(super) fn clone_remembered_set_for_direct_heap_field_write_barriers(
        &self,
        remembered_set: &RememberedSet,
    ) -> Result<RememberedSet, EvalHeapError> {
        let mut staged = RememberedSet::with_epoch(remembered_set.epoch());
        for edge in remembered_set.edges() {
            staged
                .record(*edge)
                .map_err(EvalHeapError::GenerationalGc)?;
        }
        Ok(staged)
    }

    pub(super) fn validate_direct_heap_field_write_requests(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        allow_young_replacements: bool,
    ) -> Result<(), EvalHeapError> {
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
        if generation != HeapGeneration::Old
            && !(allow_young_replacements && generation == HeapGeneration::Young)
        {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteYoungReplacementUnsupported {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    generation,
                },
            );
        }

        Ok(())
    }

    pub(super) fn validate_direct_heap_field_writeback_generation(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        record: &HeapRecord,
    ) -> Result<(), EvalHeapError> {
        let expected = expected_direct_heap_field_write_generation(write.allocation_domain());
        let actual = generation_for_record(record);
        if record.allocation_domain != write.allocation_domain() || actual != expected {
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

    pub(super) fn validate_direct_heap_field_replacement_generation(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
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
                EvalHeapError::CollectorPollDirectHeapFieldWriteReplacementGenerationMismatch {
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

    pub(super) fn object_body_binding_tag(
        &self,
        request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Result<ValueTag, EvalHeapError> {
        let source = self.record_for_minor_gc_survivor(request.source())?;
        Ok(source.object.tag())
    }
}
