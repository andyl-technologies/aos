//! The allocation-poll minor-GC commit plan and its staged inputs.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

/// Commit metadata for an allocation-poll minor-GC plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcCommitPlan<'a> {
    pub(super) reference_slots: &'a [AllocationCollectorPollReferenceSlot],
    pub(super) heap_records: usize,
    pub(super) worker_region_owner: u64,
    pub(super) worker_region_epoch: u64,
    pub(super) allocation_safepoints: AllocationSafepointState,
    pub(super) permanent_allocation_safepoints: AllocationSafepointState,
    pub(super) commit_plan: MinorGcCommitPlan,
}

impl<'a> AllocationCollectorPollMinorGcCommitPlan<'a> {
    /// Returns the copied reference-slot labels used by the rewrite plan.
    pub const fn reference_slots(&self) -> &'a [AllocationCollectorPollReferenceSlot] {
        self.reference_slots
    }

    /// Returns the ordered lower-level minor-GC commit plan.
    pub const fn commit_plan(&self) -> &MinorGcCommitPlan {
        &self.commit_plan
    }

    /// Returns the typed heap record count captured when this commit was planned.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured when this commit was planned.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured when this commit was planned.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns the worker allocation-safepoint state captured by this commit.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns the permanent allocation-safepoint state captured by this commit.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }

    /// Derives empty forwarding slots for caller-owned commit application.
    ///
    /// Slots are emitted in the lower-level forwarding-pointer order, using each
    /// pointer's from-space source address. The returned buffer is caller-owned
    /// and suitable for the forwarding-slot slice passed to
    /// [`AllocationCollectorPollMinorGcCommitPlan::apply_to_buffers`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding-slot storage cannot be reserved.
    pub fn forwarding_slot_buffer(&self) -> Result<Vec<MinorGcForwardingSlot>, EvalHeapError> {
        let pointers = self.commit_plan.forwarding_pointers().pointers();
        let mut slots = Vec::new();
        slots.try_reserve_exact(pointers.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries: pointers.len(),
            }
        })?;
        for pointer in pointers {
            slots.push(MinorGcForwardingSlot::new(pointer.source()));
        }
        Ok(slots)
    }

    /// Derives writeback metadata for root-backed minor-GC rewrites.
    ///
    /// The returned plan contains only copied tree-walk/JIT root slots that the
    /// lower-level commit plan will rewrite. Heap-field slots are skipped because
    /// [`EvalHeap::collector_poll_minor_gc_heap_field_writeback_plan`] binds those
    /// to typed heap fields. This remains metadata only: it does not own or mutate
    /// live value-stack, frame, continuation, import-cache, or stack-map storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if writeback storage cannot be reserved, if a
    /// lower-level rewrite slot is out of bounds for the copied reference labels,
    /// if a copied root slot no longer matches its lower-level rewrite source,
    /// or if a root-backed copied slot is missing the value tag needed for later
    /// typed `Value` reconstruction.
    pub fn root_writeback_plan(
        &self,
    ) -> Result<AllocationCollectorPollRootWritebackPlan, EvalHeapError> {
        let rewrites = self.commit_plan.reference_rewrites().rewrites();
        let mut writebacks = Vec::new();

        for rewrite in rewrites {
            let slot_index = rewrite.slot();
            let slot =
                self.reference_slot_for_rewrite(slot_index, MINOR_GC_ROOT_WRITEBACKS_TABLE)?;
            let AllocationCollectorPollReferenceSource::Root { source } = slot.source() else {
                continue;
            };
            let expected = validate_reference_slot_matches_rewrite(slot_index, slot, *rewrite)?;
            let value_tag = slot.value_tag().ok_or(
                EvalHeapError::CollectorPollRootWritebackMissingValueTag {
                    index: slot_index,
                    root_source: source.clone(),
                },
            )?;
            let entries =
                writebacks
                    .len()
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_ROOT_WRITEBACKS_TABLE,
                    })?;
            writebacks.try_reserve_exact(1).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_ROOT_WRITEBACKS_TABLE,
                    entries,
                }
            })?;
            writebacks.push(AllocationCollectorPollRootWriteback::new(
                slot_index,
                source.clone(),
                expected,
                value_tag,
                rewrite.replacement(),
                value_tag,
            ));
        }

        Ok(AllocationCollectorPollRootWritebackPlan::new(writebacks))
    }

    /// Applies this allocation-poll commit plan to caller-owned buffers.
    ///
    /// The allocation-poll layer first checks that the caller supplied the same
    /// reference values captured with the copied poll reference labels. It then
    /// delegates byte-copy buffers, forwarding slots, reference values,
    /// remembered-set state, and any optional card-table buffer to the
    /// lower-level validated commit plan. This remains a caller-buffer bridge
    /// and does not bind those buffers to live evaluator roots, heap-object
    /// fields, object headers, live card-table storage, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// buffer no longer matches the validated minor-GC commit plan.
    pub fn apply_to_buffers(
        self,
        buffers: AllocationCollectorPollMinorGcCommitBuffers<'_, '_>,
    ) -> Result<(), EvalHeapError> {
        self.apply_to_buffers_with_report(buffers).map(|_| ())
    }

    /// Applies this allocation-poll commit plan and reports committed counts.
    ///
    /// This has the same reference-label validation and lower-level commit
    /// order as [`Self::apply_to_buffers`], but returns the lower-level
    /// [`MinorGcCommitReport`] after all caller-owned buffers have been
    /// mutated. The report describes the validated buffer commit only; this
    /// method still does not mutate live evaluator roots, heap fields, object
    /// headers, live card-table storage, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// buffer no longer matches the validated minor-GC commit plan.
    pub fn apply_to_buffers_with_report(
        self,
        buffers: AllocationCollectorPollMinorGcCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, EvalHeapError> {
        let AllocationCollectorPollMinorGcCommitBuffers {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        self.validate_commit_references(references)?;

        let lower_buffers = match card_table {
            Some(card_table) => MinorGcCommitBuffers::with_card_table(
                object_byte_copies,
                forwarding_slots,
                references,
                remembered_set,
                card_table,
            ),
            None => MinorGcCommitBuffers::new(
                object_byte_copies,
                forwarding_slots,
                references,
                remembered_set,
            ),
        };
        self.commit_plan
            .apply_to_buffers_with_report(lower_buffers)
            .map_err(EvalHeapError::from)
    }

    /// Applies this allocation-poll commit plan to owned destination storage.
    ///
    /// The allocation-poll layer first checks that the caller supplied the same
    /// reference values captured with the copied poll reference labels. It then
    /// delegates owned destination storage, source bytes, forwarding slots,
    /// reference values, remembered-set state, and any optional card-table
    /// buffer to the lower-level validated commit plan. This remains an
    /// owned-buffer bridge and does not bind storage to live evaluator roots,
    /// heap-object fields, object headers, live card-table storage, or semispace
    /// pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// state no longer matches the validated minor-GC commit plan.
    pub fn apply_to_owned_destination_storage(
        self,
        buffers: AllocationCollectorPollMinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<(), EvalHeapError> {
        self.apply_to_owned_destination_storage_with_report(buffers)
            .map(|_| ())
    }

    /// Applies this allocation-poll commit plan to owned storage and reports counts.
    ///
    /// This has the same reference-label validation and lower-level commit order
    /// as [`Self::apply_to_owned_destination_storage`], but returns the
    /// lower-level [`MinorGcCommitReport`] after all owned storage and metadata
    /// buffers have been mutated.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// state no longer matches the validated minor-GC commit plan.
    pub fn apply_to_owned_destination_storage_with_report(
        self,
        buffers: AllocationCollectorPollMinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, EvalHeapError> {
        let AllocationCollectorPollMinorGcOwnedCommitBuffers {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        self.validate_commit_references(references)?;

        let lower_buffers = match card_table {
            Some(card_table) => MinorGcOwnedCommitBuffers::with_card_table(
                destination_storage,
                source_bytes,
                forwarding_slots,
                references,
                remembered_set,
                card_table,
            ),
            None => MinorGcOwnedCommitBuffers::new(
                destination_storage,
                source_bytes,
                forwarding_slots,
                references,
                remembered_set,
            ),
        };
        self.commit_plan
            .apply_to_owned_destination_storage_with_report(lower_buffers)
            .map_err(EvalHeapError::from)
    }

    pub(super) fn validate_commit_references(
        &self,
        references: &[ResolvedValueGeneration],
    ) -> Result<(), EvalHeapError> {
        if references.len() != self.reference_slots.len() {
            return Err(
                EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
                    expected: self.reference_slots.len(),
                    actual: references.len(),
                },
            );
        }
        for (index, (slot, actual)) in self
            .reference_slots
            .iter()
            .zip(references.iter().copied())
            .enumerate()
        {
            let expected = slot.value();
            if actual != expected {
                return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                    index,
                    expected,
                    actual,
                });
            }
        }
        Ok(())
    }

    pub(super) fn reference_slot_for_rewrite(
        &self,
        slot_index: usize,
        table: &'static str,
    ) -> Result<&AllocationCollectorPollReferenceSlot, EvalHeapError> {
        let Some(slot) = self.reference_slots.get(slot_index) else {
            let expected = slot_index
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow { table })?;
            return Err(
                EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
                    expected,
                    actual: self.reference_slots.len(),
                },
            );
        };
        Ok(slot)
    }
}
