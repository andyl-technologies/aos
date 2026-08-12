//! impl EvalHeap: forwarding-value installation/validation and the
//! collector-poll reference/writeback buffer and plan builders.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

impl EvalHeap {
    /// Returns the live side-table forwarding value installed for `address`.
    ///
    /// This exposes evaluator-owned forwarding metadata used by the tree-walk
    /// GC-stress bridge. It does not read an ABI object header or prove that
    /// destination object storage has been allocated.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `address` does not belong to this heap.
    pub fn minor_gc_forwarding_value_at(
        &self,
        address: GcHeapAddress,
    ) -> Result<Option<ResolvedValueGeneration>, EvalHeapError> {
        Ok(self
            .record_for_gc_address(address, "forwarding source")?
            .minor_gc_forwarding
            .get())
    }

    pub(super) fn alloc_minor_gc_destination_record_like(
        &mut self,
        source: GcHeapAddress,
        tag: ValueTag,
    ) -> Result<Value, EvalHeapError> {
        if matches!(tag, ValueTag::Lambda | ValueTag::Primop | ValueTag::Thunk) {
            self.alloc_minor_gc_destination_worker_record(source, tag)
        } else {
            Err(
                EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                    source_address: source,
                    tag,
                },
            )
        }
    }

    pub(super) fn validate_minor_gc_destination_record_reservation(
        &self,
        reservation: AllocationCollectorPollMinorGcDestinationRecordReservation,
    ) -> Result<(), EvalHeapError> {
        let source = self.record_for_minor_gc_survivor(reservation.source())?;
        let Some(destination) = self
            .records
            .record_at_address(reservation.destination().address_bits())
        else {
            return Err(EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: reservation.destination(),
            });
        };

        if source.object.tag() != reservation.tag() || destination.object.tag() != reservation.tag()
        {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: reservation.source(),
                destination: reservation.destination(),
                reason: "reserved destination record tag does not match source record tag",
            });
        }
        if !heap_record_layout_matches(
            destination.layout,
            source.layout.size_bytes,
            source.layout.align,
        ) {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteLayoutMismatch {
                address: reservation.destination(),
                expected_size: source.layout.size_bytes,
                actual_size: destination.layout.size_bytes,
                expected_align: source.layout.align,
                actual_align: destination.layout.align,
            });
        }

        Ok(())
    }

    /// Returns every installed live side-table forwarding value.
    ///
    /// This exposes evaluator-owned forwarding metadata used by the tree-walk
    /// GC-stress bridge. It snapshots occupied side-table cells in heap-record
    /// order, and does not read ABI object headers, prove destination storage
    /// exists, or validate destination generations.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding value storage cannot be reserved
    /// or a heap record cannot be converted back into a GC address.
    pub fn minor_gc_forwarding_values(
        &self,
    ) -> Result<Vec<AllocationCollectorPollForwardingValue>, EvalHeapError> {
        let forwarding_value_count = self
            .records
            .iter()
            .filter(|record| record.minor_gc_forwarding.get().is_some())
            .count();
        let mut forwarding_values = Vec::new();
        forwarding_values
            .try_reserve_exact(forwarding_value_count)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_FORWARDING_VALUES_TABLE,
                entries: forwarding_value_count,
            })?;

        for record in &self.records {
            let Some(forwarded_value) = record.minor_gc_forwarding.get() else {
                continue;
            };
            forwarding_values.push(AllocationCollectorPollForwardingValue::new(
                gc_address_for_record(record)?,
                forwarded_value,
            ));
        }

        Ok(forwarding_values)
    }

    /// Installs live side-table forwarding values for a minor-GC commit.
    ///
    /// Each supplied slot must be occupied, must name a current young
    /// worker-domain source object, and that object's live forwarding cell must
    /// still be empty. All slots are validated before any heap record is
    /// mutated, so validation failures leave every forwarding cell unchanged.
    /// This is an evaluator side-table bridge for GC-stress execution; it does
    /// not write ABI object headers, copy object bytes, rewrite roots or fields,
    /// publish remembered sets, clear card-table storage, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a slot is empty, duplicated, references an
    /// unknown or non-young source object, or if the source object's forwarding
    /// cell is already occupied.
    pub fn install_collector_poll_minor_gc_forwarding_slots(
        &mut self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<AllocationCollectorPollForwardingInstallReport, EvalHeapError> {
        let staged = self.stage_collector_poll_minor_gc_forwarding_slots(slots)?;
        Ok(self.commit_collector_poll_minor_gc_staged_forwarding_slots(staged))
    }

    /// Validates live evaluator heap forwarding slots without installing them.
    ///
    /// This performs the same checks as
    /// [`Self::install_collector_poll_minor_gc_forwarding_slots`] while leaving
    /// every source object's forwarding cell unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a slot is empty, duplicated, references an
    /// unknown or non-young source object, or if the source object's forwarding
    /// cell is already occupied.
    pub fn validate_collector_poll_minor_gc_forwarding_slots(
        &self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<AllocationCollectorPollForwardingInstallReport, EvalHeapError> {
        let staged = self.stage_collector_poll_minor_gc_forwarding_slots(slots)?;
        Ok(staged.report())
    }

    /// Stages live evaluator heap forwarding slots without installing them.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::install_collector_poll_minor_gc_forwarding_slots`].
    pub(crate) fn stage_collector_poll_minor_gc_forwarding_slots(
        &self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<AllocationCollectorPollForwardingInstallStage, EvalHeapError> {
        let planned = self.collector_poll_minor_gc_forwarding_slot_plan(slots)?;
        Ok(AllocationCollectorPollForwardingInstallStage { planned })
    }

    /// Commits a prevalidated evaluator heap forwarding slot stage.
    pub(crate) fn commit_collector_poll_minor_gc_staged_forwarding_slots(
        &mut self,
        staged: AllocationCollectorPollForwardingInstallStage,
    ) -> AllocationCollectorPollForwardingInstallReport {
        let report = staged.report();
        for (record_index, _, forwarded) in staged.planned {
            self.records[record_index]
                .minor_gc_forwarding
                .set(Some(forwarded));
        }
        report
    }

    pub(super) fn collector_poll_minor_gc_forwarding_slot_plan(
        &self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<Vec<(usize, GcHeapAddress, ResolvedValueGeneration)>, EvalHeapError> {
        let mut planned = Vec::new();
        planned.try_reserve_exact(slots.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries: slots.len(),
            }
        })?;

        for (index, slot) in slots.iter().copied().enumerate() {
            let Some(forwarded) = slot.forwarded_value() else {
                return Err(EvalHeapError::CollectorPollForwardingSlotEmpty {
                    index,
                    address: slot.source(),
                });
            };
            if planned.iter().any(
                |(_, source, _): &(usize, GcHeapAddress, ResolvedValueGeneration)| {
                    *source == slot.source()
                },
            ) {
                return Err(EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
                    index,
                    address: slot.source(),
                });
            }

            let record_index = self.record_index_for_minor_gc_survivor(slot.source())?;
            if let Some(actual) = self.records[record_index].minor_gc_forwarding.get() {
                return Err(EvalHeapError::GenerationalGc(
                    GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
                        index,
                        address: slot.source(),
                        actual,
                    },
                ));
            }
            planned.push((record_index, slot.source(), forwarded));
        }

        Ok(planned)
    }

    /// Derives a reference buffer for heap-field-backed commit slots.
    ///
    /// This is a live side-table binding precursor for remembered-source fields,
    /// dirty old fields, and copied nursery fields. It validates that each saved
    /// field index still points at the same [`HeapEdgeSource`] label before
    /// reading the current value. Copied tree-walk/JIT root slots are rejected
    /// because [`EvalHeap`] does not own their mutable storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if any reference slot is root-backed,
    /// if a saved field object no longer belongs to the heap, if a saved field
    /// index or label is stale, if current field scanning fails, or if the
    /// reference buffer cannot reserve storage.
    pub fn collector_poll_minor_gc_heap_field_reference_buffer(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let reference_slots = commit_plan.reference_slots();
        let mut references = Vec::new();
        references
            .try_reserve_exact(reference_slots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_REFERENCE_BUFFER_TABLE,
                entries: reference_slots.len(),
            })?;
        for (index, slot) in reference_slots.iter().enumerate() {
            references.push(self.current_heap_field_reference_value(index, slot.source())?);
        }
        Ok(references)
    }

    /// Derives a complete commit reference buffer in copied slot order.
    ///
    /// `root_values` must contain one current root value for every copied root
    /// reference slot in [`AllocationCollectorPollMinorGcCommitPlan::reference_slots`]
    /// order, including roots that will not be rewritten by the lower-level
    /// reference-rewrite plan. Heap-field-backed slots are read and revalidated
    /// from the current typed heap side table. The returned buffer is caller-owned
    /// and suitable for the reference slice passed to
    /// [`AllocationCollectorPollMinorGcCommitPlan::apply_to_buffers`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if the caller supplies too few or too
    /// many root values, if a supplied root source or value no longer matches the
    /// copied reference slot, if a heap-field slot is stale, or if the reference
    /// buffer cannot reserve storage.
    pub fn collector_poll_minor_gc_reference_buffer(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
        root_values: &[AllocationCollectorPollRootReferenceValue],
    ) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let reference_slots = commit_plan.reference_slots();
        let expected_roots = reference_slots.iter().filter(|slot| slot.is_root()).count();
        if root_values.len() != expected_roots {
            return Err(
                EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
                    expected: expected_roots,
                    actual: root_values.len(),
                },
            );
        }

        let mut references = Vec::new();
        references
            .try_reserve_exact(reference_slots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_REFERENCE_BUFFER_TABLE,
                entries: reference_slots.len(),
            })?;

        let mut root_index = 0usize;
        for (index, slot) in reference_slots.iter().enumerate() {
            let value = match slot.source() {
                AllocationCollectorPollReferenceSource::Root { source } => {
                    let Some(root_value) = root_values.get(root_index) else {
                        return Err(
                            EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
                                expected: expected_roots,
                                actual: root_values.len(),
                            },
                        );
                    };
                    root_index =
                        root_index
                            .checked_add(1)
                            .ok_or(EvalHeapError::RootScanLengthOverflow {
                                table: MINOR_GC_REFERENCE_BUFFER_TABLE,
                            })?;
                    if root_value.source() != source {
                        return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                            index,
                            expected: source.clone(),
                            actual: root_value.source().clone(),
                        });
                    }
                    root_value.value()
                }
                _ => self.current_heap_field_reference_value(index, slot.source())?,
            };
            let expected = slot.value();
            if value != expected {
                return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                    index,
                    expected,
                    actual: value,
                });
            }
            references.push(value);
        }

        Ok(references)
    }

    /// Derives writeback metadata for heap-field-backed minor-GC rewrites.
    ///
    /// The returned plan contains only remembered-source, dirty old-field, and
    /// nursery-field slots that the lower-level commit plan will rewrite. Root
    /// slots are skipped because their mutable storage is owned by the active
    /// tree-walk/JIT safepoint machinery, not by [`EvalHeap`]. Every heap-field
    /// slot is re-read from the current typed side table before it is admitted
    /// so stale field labels or changed field values fail before a future
    /// mutating writeback.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if writeback storage cannot be
    /// reserved, if a saved field object no longer belongs to the heap, if a saved
    /// field index or label is stale, if a copied slot no longer matches its
    /// lower-level rewrite, or if the current field value no longer matches the
    /// copied poll slot value.
    pub fn collector_poll_minor_gc_heap_field_writeback_plan(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<AllocationCollectorPollHeapFieldWritebackPlan, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let rewrites = commit_plan.commit_plan().reference_rewrites().rewrites();
        let reference_slots = commit_plan.reference_slots();
        let mut writebacks = Vec::new();
        writebacks.try_reserve_exact(rewrites.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries: rewrites.len(),
            }
        })?;

        for rewrite in rewrites {
            let slot_index = rewrite.slot();
            let Some(slot) = reference_slots.get(slot_index) else {
                let expected =
                    slot_index
                        .checked_add(1)
                        .ok_or(EvalHeapError::RootScanLengthOverflow {
                            table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                        })?;
                return Err(
                    EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
                        expected,
                        actual: reference_slots.len(),
                    },
                );
            };
            let Some((validation_object, writeback_object, field_index, source)) =
                heap_field_writeback_source(
                    slot.source(),
                    commit_plan.commit_plan().object_copies(),
                )?
            else {
                continue;
            };
            let expected = validate_reference_slot_matches_rewrite(slot_index, slot, *rewrite)?;
            let actual = self.current_heap_field_reference_value_at(
                slot_index,
                validation_object,
                field_index,
                source,
            )?;
            if actual != expected {
                return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                    index: slot_index,
                    expected,
                    actual,
                });
            }
            writebacks.push(AllocationCollectorPollHeapFieldWriteback::new(
                slot_index,
                validation_object,
                writeback_object,
                field_index,
                source.clone(),
                expected,
                rewrite.replacement(),
            ));
        }

        Ok(AllocationCollectorPollHeapFieldWritebackPlan::new(
            writebacks,
        ))
    }

    /// Reads current heap-field values for a derived writeback plan.
    ///
    /// The returned slots preserve the plan's writeback order and copied field
    /// labels, but their values come from the current typed heap side table. This
    /// lets higher-level safepoint bridges validate caller-owned heap-field
    /// buffers immediately before applying reference writebacks.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if slot storage cannot be reserved, if a saved
    /// field object no longer belongs to the heap, if a saved field index or
    /// label is stale, or if the current field value cannot be classified.
    pub fn collector_poll_minor_gc_heap_field_writeback_slots(
        &self,
        plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    ) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
        let writebacks = plan.writebacks();
        let mut slots = Vec::new();
        slots.try_reserve_exact(writebacks.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries: writebacks.len(),
            }
        })?;

        for writeback in writebacks {
            let value = self.current_heap_field_reference_value_at(
                writeback.slot(),
                writeback.validation_object(),
                writeback.field_index(),
                writeback.source(),
            )?;
            slots.push(AllocationCollectorPollHeapFieldWritebackSlot::new(
                writeback.validation_object(),
                writeback.writeback_object(),
                writeback.field_index(),
                writeback.source().clone(),
                value,
            ));
        }

        Ok(slots)
    }

    pub(crate) fn collector_poll_minor_gc_live_heap_field_write_inputs(
        &self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    ) -> Result<
        (
            Vec<AllocationCollectorPollCopiedHeapFieldWrite>,
            Vec<AllocationCollectorPollDirectHeapFieldWrite>,
        ),
        EvalHeapError,
    > {
        let writebacks = plan.writebacks();
        let mut copied_writes = Vec::new();
        let mut direct_writes = Vec::new();
        copied_writes
            .try_reserve_exact(writebacks.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writebacks.len(),
            })?;
        direct_writes
            .try_reserve_exact(writebacks.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writebacks.len(),
            })?;

        for writeback in writebacks {
            let allocation_domain = self.allocation_domain_for_address(
                writeback.validation_object(),
                "heap-field writeback validation object",
            )?;
            let replacement_request = object_copy_request_for_reference_writeback(
                object_body_plan,
                writeback.slot(),
                writeback.expected(),
                writeback.replacement(),
            )?;
            if writeback.validation_object() == writeback.writeback_object() {
                direct_writes.push(AllocationCollectorPollDirectHeapFieldWrite::new(
                    allocation_domain,
                    writeback.writeback_object(),
                    writeback.field_index(),
                    writeback.source().clone(),
                    writeback.replacement(),
                    replacement_request,
                ));
            } else {
                let writeback_object_request = object_copy_request_for_reference_writeback_address(
                    object_body_plan,
                    writeback.slot(),
                    writeback.validation_object(),
                    writeback.writeback_object(),
                )?;
                copied_writes.push(AllocationCollectorPollCopiedHeapFieldWrite::new(
                    allocation_domain,
                    writeback.validation_object(),
                    writeback.writeback_object(),
                    writeback.field_index(),
                    writeback.source().clone(),
                    writeback.replacement(),
                    replacement_request,
                    writeback_object_request,
                ));
            }
        }

        validate_collector_poll_minor_gc_reference_writeback_direct_destination_aliases(
            object_body_plan,
            &direct_writes,
        )?;

        Ok((copied_writes, direct_writes))
    }

    /// Derives all root-backed and heap-field-backed reference writebacks.
    ///
    /// This composes [`AllocationCollectorPollMinorGcCommitPlan::root_writeback_plan`]
    /// with [`Self::collector_poll_minor_gc_heap_field_writeback_plan`]. Root
    /// writebacks remain metadata for externally owned tree-walk/JIT slots, while
    /// heap-field writebacks are revalidated against current typed heap fields.
    /// The helper still does not mutate live roots or heap objects.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if root writeback metadata cannot be
    /// built, or if heap-field writeback validation fails.
    pub fn collector_poll_minor_gc_reference_writeback_plan(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<AllocationCollectorPollReferenceWritebackPlan, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let root_writebacks = commit_plan.root_writeback_plan()?;
        let heap_field_writebacks =
            self.collector_poll_minor_gc_heap_field_writeback_plan(commit_plan)?;
        Ok(AllocationCollectorPollReferenceWritebackPlan::new(
            root_writebacks,
            heap_field_writebacks,
        ))
    }
}
