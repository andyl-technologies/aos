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
        staged_flat_closures: &mut Vec<StagedFlatClosureWrite>,
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
                HeapFieldWriteTarget::FlatClosure(ptr, kind) => {
                    let live = self.flat_closure_payload_any(ptr).ok_or(
                        EvalHeapError::UnknownCollectorPollReferenceSlotAddress {
                            address: write.writeback_object,
                        },
                    )?;
                    if staged_environment
                        .stage_flat_closure(live, &write.source, write.replacement)
                        .map_err(EvalHeapError::Environment)?
                    {
                        continue;
                    }
                    let staged_write = self.staged_flat_closure_heap_field_write_object_mut(
                        staged_flat_closures,
                        ptr,
                        kind,
                        MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                        entries,
                    )?;
                    match &write.source {
                        HeapEdgeSource::CapturedFlatEnv { owner, index } => {
                            let expected_owner = match kind {
                                FlatObjectKind::Lambda => CapturedRootOwner::Lambda,
                                FlatObjectKind::Thunk => CapturedRootOwner::Thunk,
                                _ => {
                                    return Err(direct_heap_field_write_object_error(
                                        write,
                                        RecordOwnedHeapFieldWriteObjectError::UnsupportedSource,
                                    ));
                                }
                            };
                            if *owner != expected_owner {
                                return Err(direct_heap_field_write_object_error(
                                    write,
                                    RecordOwnedHeapFieldWriteObjectError::UnsupportedSource,
                                ));
                            }
                            let Some(tail) = staged_write.tail.as_mut() else {
                                return Err(direct_heap_field_write_object_error(
                                    write,
                                    RecordOwnedHeapFieldWriteObjectError::UnsupportedSource,
                                ));
                            };
                            let Some(slot) = tail.get_mut(*index) else {
                                return Err(direct_heap_field_write_object_error(
                                    write,
                                    RecordOwnedHeapFieldWriteObjectError::UnsupportedSource,
                                ));
                            };
                            *slot = write.replacement;
                        }
                        _ => {
                            staged_write.payload = flat_closure_heap_field_write_object(
                                &staged_write.payload,
                                &write.source,
                                write.replacement,
                            )
                            .map_err(|error| direct_heap_field_write_object_error(write, error))?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns a complete staged flat closure, cloning it on first touch.
    ///
    /// The payload and optional inline value tail are copied before any live
    /// mutation. Retired closures are rejected. A shared thunk is retained as
    /// the same `Arc`; payload-owned rewrites subsequently fail closed because
    /// rebuilding the thunk would change the identity observed by force clones.
    pub(super) fn staged_flat_closure_heap_field_write_object_mut<'a>(
        &self,
        staged: &'a mut Vec<StagedFlatClosureWrite>,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut StagedFlatClosureWrite, EvalHeapError> {
        if let Some(index) = staged.iter().position(|existing| existing.ptr == ptr) {
            if staged[index].kind != kind {
                return Err(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "staged flat closure kind changed",
                });
            }
            return Ok(&mut staged[index]);
        }
        let (object, tail) = self
            .flat_closures
            .resolve_with_value_tail(ptr, kind)
            .map_err(|error| {
                self.closure_resolution_error(value_tag_for_flat_kind(kind), ptr, error)
            })?;
        let payload = match object.payload() {
            FlatClosurePayload::Thunk(thunk) => StagedFlatClosurePayload::Thunk(thunk.clone()),
            FlatClosurePayload::SharedThunk(thunk) => {
                StagedFlatClosurePayload::SharedThunk(Arc::clone(thunk))
            }
            FlatClosurePayload::Lambda(lambda) => StagedFlatClosurePayload::Lambda(lambda.clone()),
            FlatClosurePayload::Primop(primop) => StagedFlatClosurePayload::Primop(primop.clone()),
            FlatClosurePayload::Retired(_) => {
                return Err(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "flat closure heap-field writeback rejects retired payloads",
                });
            }
        };
        let tail = tail.map(<[Value]>::to_vec);
        staged.push(StagedFlatClosureWrite {
            ptr,
            kind,
            payload,
            tail,
        });
        let Some(write) = staged.last_mut() else {
            return Err(EvalHeapError::RootScanAllocationFailed { table, entries });
        };
        Ok(write)
    }

    /// Commits staged nursery closure payloads and tails through the exclusive door.
    ///
    /// Every variable-size clone and validation happens during staging.
    /// Publication performs only payload moves and same-length slice copies.
    ///
    /// # Panics
    ///
    /// Panics if a staged address no longer resolves as the validated closure
    /// kind, which would violate the exclusive staging/commit invariant.
    pub(in crate::eval::heap) fn commit_collector_poll_minor_gc_staged_flat_closure_writes(
        &mut self,
        staged: Vec<StagedFlatClosureWrite>,
    ) {
        for write in staged {
            let (payload, tail) = match self
                .flat_closures
                .resolve_mut_with_value_tail(write.ptr, write.kind)
            {
                Ok(resolved) => resolved,
                Err(error) => {
                    unreachable!("staged flat-closure writeback failed to resolve: {error}")
                }
            };
            let staged_tail_len = write.tail.as_ref().map(Vec::len);
            let live_tail_len = tail.as_deref().map(<[Value]>::len);
            if staged_tail_len != live_tail_len {
                unreachable!("staged flat-closure tail shape changed before commit");
            }
            *payload = write.payload.into_flat_payload();
            if let (Some(destination), Some(source)) = (tail, write.tail) {
                destination.copy_from_slice(&source);
            }
        }
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

    pub(in crate::eval::heap) fn commit_collector_poll_minor_gc_staged_heap_field_writes(
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

#[cfg(test)]
mod flat_closure_writeback_tests {
    use std::sync::Arc;

    use super::*;
    use crate::eval::EvalFrame;

    fn stage_flat_closure_writes(
        heap: &EvalHeap,
        writes: &[CollectorPollDirectHeapFieldWrite],
    ) -> Result<(Vec<StagedFlatClosureWrite>, EnvironmentWritebackStage), EvalHeapError> {
        let mut records = Vec::new();
        let mut lists = Vec::new();
        let mut attrs = Vec::new();
        let mut closures = Vec::new();
        let mut environments = EnvironmentWritebackStage::try_new(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;
        heap.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            writes,
            &mut records,
            &mut lists,
            &mut attrs,
            &mut closures,
            &mut environments,
            writes.len(),
        )?;
        Ok((closures, environments))
    }

    #[test]
    fn staged_flat_primop_write_is_invisible_until_commit() {
        let mut heap = EvalHeap::new();
        let original = Value::int(1);
        let replacement = Value::int(2);
        let parent = heap
            .alloc_primop(EvalPrimOp::with_args(
                Symbol::new(1),
                vec![EvalPrimOpArg::new(IrId::new(1), Span::new(0, 1), original)],
            ))
            .expect("flat primop allocates");
        let (_, ptr) = heap_ptr(parent).expect("parent has a heap pointer");
        let address = GcHeapAddress::new(ptr.as_ptr() as usize).expect("address is nonzero");
        let writes = [CollectorPollDirectHeapFieldWrite {
            target: HeapFieldWriteTarget::FlatClosure(ptr, FlatObjectKind::Primop),
            writeback_object: address,
            field_index: 0,
            source: HeapEdgeSource::PrimopArgument { index: 0 },
            replacement,
            remembered_edge: None,
        }];
        let mut records = Vec::new();
        let mut lists = Vec::new();
        let mut attrs = Vec::new();
        let mut closures = Vec::new();
        let mut environments = EnvironmentWritebackStage::try_new(1).expect("stage reserves");

        heap.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &writes,
            &mut records,
            &mut lists,
            &mut attrs,
            &mut closures,
            &mut environments,
            1,
        )
        .expect("write stages");
        assert!(
            heap.get_primop(parent).expect("primop resolves").args()[0]
                .value()
                .raw_eq(original)
        );

        heap.commit_collector_poll_minor_gc_staged_flat_closure_writes(closures);
        environments.commit();
        assert!(
            heap.get_primop(parent).expect("primop resolves").args()[0]
                .value()
                .raw_eq(replacement)
        );
    }

    #[test]
    fn failed_flat_lambda_preflight_leaves_payload_and_shared_frame_untouched() {
        let mut heap = EvalHeap::new();
        let original = Value::int(11);
        let replacement = Value::int(12);
        let frame = EvalFrame::new(1).expect("frame allocates");
        frame.set(0, original).expect("frame initializes");
        let parent = heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(2),
                IrId::new(3),
                FrameId::new(4),
                EvalEnv::capture(&[Arc::clone(&frame)]).expect("environment captures"),
            ))
            .expect("flat lambda allocates");
        let (_, ptr) = heap_ptr(parent).expect("parent has a heap pointer");
        let address = GcHeapAddress::new(ptr.as_ptr() as usize).expect("address is nonzero");
        let writes = [
            CollectorPollDirectHeapFieldWrite {
                target: HeapFieldWriteTarget::FlatClosure(ptr, FlatObjectKind::Lambda),
                writeback_object: address,
                field_index: 0,
                source: HeapEdgeSource::CapturedEnv {
                    owner: CapturedRootOwner::Lambda,
                    frame: 0,
                    slot: 0,
                },
                replacement,
                remembered_edge: None,
            },
            CollectorPollDirectHeapFieldWrite {
                target: HeapFieldWriteTarget::FlatClosure(ptr, FlatObjectKind::Lambda),
                writeback_object: address,
                field_index: 1,
                source: HeapEdgeSource::ListElement { index: 0 },
                replacement,
                remembered_edge: None,
            },
        ];
        let mut records = Vec::new();
        let mut lists = Vec::new();
        let mut attrs = Vec::new();
        let mut closures = Vec::new();
        let mut environments = EnvironmentWritebackStage::try_new(2).expect("stage reserves");

        heap.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &writes,
            &mut records,
            &mut lists,
            &mut attrs,
            &mut closures,
            &mut environments,
            2,
        )
        .expect_err("unsupported second source rejects the complete stage");

        assert!(frame.get(0).expect("captured slot reads").raw_eq(original));
        let lambda = heap.get_lambda(parent).expect("lambda remains live");
        assert!(
            lambda.env().frames()[0]
                .get(0)
                .expect("lambda capture reads")
                .raw_eq(original)
        );
    }

    #[test]
    fn staged_flat_lambda_tail_write_is_invisible_until_commit() {
        let mut heap = EvalHeap::new();
        let original = Value::int(21);
        let replacement = Value::int(22);
        let site = EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(20));
        let mut capture = EvalFlatCaptureBuffer::new(site, 1);
        capture.push(original).expect("capture value fits");
        let (parent, _) = heap
            .alloc_lambda_with_flat_capture(
                EvalLambda::new(
                    IrId::new(23),
                    IrId::new(24),
                    FrameId::new(25),
                    EvalEnv::default(),
                ),
                Some(capture.finish()),
            )
            .expect("flat lambda with tail allocates");
        let (_, ptr) = heap_ptr(parent).expect("parent has a heap pointer");
        let address = GcHeapAddress::new(ptr.as_ptr() as usize).expect("address is nonzero");
        let writes = [CollectorPollDirectHeapFieldWrite {
            target: HeapFieldWriteTarget::FlatClosure(ptr, FlatObjectKind::Lambda),
            writeback_object: address,
            field_index: 1,
            source: HeapEdgeSource::CapturedFlatEnv {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            replacement,
            remembered_edge: None,
        }];

        let (closures, environments) =
            stage_flat_closure_writes(&heap, &writes).expect("tail write stages");
        let before = heap
            .flat_closures
            .value_tail(ptr, FlatObjectKind::Lambda)
            .expect("tail resolves")
            .expect("tail is present");
        assert!(before[0].raw_eq(original));

        heap.commit_collector_poll_minor_gc_staged_flat_closure_writes(closures);
        environments.commit();
        let after = heap
            .flat_closures
            .value_tail(ptr, FlatObjectKind::Lambda)
            .expect("tail resolves")
            .expect("tail is present");
        assert!(after[0].raw_eq(replacement));
    }

    #[test]
    fn staged_suspended_flat_thunk_field_is_invisible_until_commit() {
        let mut heap = EvalHeap::new();
        let original = Value::int(31);
        let replacement = Value::int(32);
        let parent = heap
            .alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(30),
                Span::new(0, 1),
                original,
                EvalModuleId::ROOT,
                IrId::new(31),
                Value::int(33),
            ))
            .expect("flat thunk allocates");
        let (_, ptr) = heap_ptr(parent).expect("parent has a heap pointer");
        let address = GcHeapAddress::new(ptr.as_ptr() as usize).expect("address is nonzero");
        let writes = [CollectorPollDirectHeapFieldWrite {
            target: HeapFieldWriteTarget::FlatClosure(ptr, FlatObjectKind::Thunk),
            writeback_object: address,
            field_index: 0,
            source: HeapEdgeSource::ThunkApplyFunction,
            replacement,
            remembered_edge: None,
        }];

        let (closures, environments) =
            stage_flat_closure_writes(&heap, &writes).expect("thunk write stages");
        let read_function = |heap: &EvalHeap| {
            let thunk = heap.get_thunk(parent).expect("thunk resolves");
            let EvalThunkKind::Apply { function_value, .. } = thunk.kind() else {
                panic!("thunk remains an application");
            };
            *function_value
        };
        assert!(read_function(&heap).raw_eq(original));

        heap.commit_collector_poll_minor_gc_staged_flat_closure_writes(closures);
        environments.commit();
        assert!(read_function(&heap).raw_eq(replacement));
    }

    #[test]
    fn staged_forced_flat_thunk_result_is_invisible_until_commit() {
        let mut heap = EvalHeap::new();
        let original = Value::int(41);
        let replacement = Value::int(42);
        let parent = heap
            .alloc_thunk(EvalThunk::released_forced(original))
            .expect("forced flat thunk allocates");
        let (_, ptr) = heap_ptr(parent).expect("parent has a heap pointer");
        let address = GcHeapAddress::new(ptr.as_ptr() as usize).expect("address is nonzero");
        let writes = [CollectorPollDirectHeapFieldWrite {
            target: HeapFieldWriteTarget::FlatClosure(ptr, FlatObjectKind::Thunk),
            writeback_object: address,
            field_index: 0,
            source: HeapEdgeSource::ThunkCachedResult,
            replacement,
            remembered_edge: None,
        }];

        let (closures, environments) =
            stage_flat_closure_writes(&heap, &writes).expect("forced result stages");
        let read_cached = |heap: &EvalHeap| {
            heap.get_thunk(parent)
                .expect("thunk resolves")
                .cell()
                .cached_value()
                .expect("cached value reads")
                .expect("forced value is present")
        };
        assert!(read_cached(&heap).raw_eq(original));

        heap.commit_collector_poll_minor_gc_staged_flat_closure_writes(closures);
        environments.commit();
        assert!(read_cached(&heap).raw_eq(replacement));
    }
}
