//! Heap-field writeback plans/slots/reports, copied/direct heap-field
//! write records, and the caller-owned commit buffers.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

/// One heap-field-backed reference that must be rewritten after minor GC.
///
/// Remembered-source and dirty old fields are validated and rewritten in the
/// same old/permanent object. Nursery fields are validated against the current
/// from-space object but name the relocated destination object that a mutating
/// collector would update after copying bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWriteback {
    slot: usize,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    expected: ResolvedValueGeneration,
    replacement: ResolvedValueGeneration,
}

impl AllocationCollectorPollHeapFieldWriteback {
    pub(super) fn new(
        slot: usize,
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        expected: ResolvedValueGeneration,
        replacement: ResolvedValueGeneration,
    ) -> Self {
        Self {
            slot,
            validation_object,
            writeback_object,
            field_index,
            source,
            expected,
            replacement,
        }
    }

    /// Returns the copied reference slot that produced this writeback.
    pub const fn slot(&self) -> usize {
        self.slot
    }

    /// Returns the current heap object read to validate the saved field label.
    pub const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    /// Returns the object whose field must receive [`Self::replacement`].
    ///
    /// This matches [`Self::validation_object`] for remembered-source and dirty
    /// old fields, and names the relocated object for copied nursery fields.
    pub const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    /// Returns the field index in the validation object's precise scanner order.
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// Returns the precise source label expected on the validation object.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the young from-space value expected in the field.
    pub const fn expected(&self) -> ResolvedValueGeneration {
        self.expected
    }

    /// Returns the relocated value that must replace [`Self::expected`].
    pub const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }
}

/// Heap-field writebacks derived from an allocation-poll minor-GC commit plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWritebackPlan {
    writebacks: Vec<AllocationCollectorPollHeapFieldWriteback>,
}

impl AllocationCollectorPollHeapFieldWritebackPlan {
    pub(super) fn new(writebacks: Vec<AllocationCollectorPollHeapFieldWriteback>) -> Self {
        Self { writebacks }
    }

    /// Returns planned heap-field writebacks in reference-rewrite order.
    pub fn writebacks(&self) -> &[AllocationCollectorPollHeapFieldWriteback] {
        &self.writebacks
    }

    /// Returns the number of heap-field writebacks.
    pub fn len(&self) -> usize {
        self.writebacks.len()
    }

    /// Returns whether there are no heap-field writebacks.
    pub fn is_empty(&self) -> bool {
        self.writebacks.is_empty()
    }

    /// Applies planned heap-field writebacks to caller-owned field slots.
    ///
    /// The supplied slots must match this plan's heap-field writeback count and
    /// order. Each slot must name the validation object, writeback object, field
    /// index, copied field source label, and expected young from-space value.
    /// The method validates every slot before rewriting any slot, so validation
    /// failures leave the caller-owned buffer unchanged. This mutates only the
    /// supplied buffer; it does not bind to live evaluator object fields,
    /// copied object bytes, object headers, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the supplied slot count differs from the
    /// plan, if a slot names a different object, field index, or field source,
    /// or if a slot no longer contains the expected young from-space value.
    pub fn apply_to_slots(
        &self,
        slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
    ) -> Result<AllocationCollectorPollHeapFieldWritebackReport, EvalHeapError> {
        validate_heap_field_writeback_slots(self, slots)?;
        apply_heap_field_writeback_slots(self, slots);

        Ok(AllocationCollectorPollHeapFieldWritebackReport {
            writebacks: self.writebacks.len(),
        })
    }
}

pub(super) fn validate_heap_field_writeback_slots(
    plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    slots: &[AllocationCollectorPollHeapFieldWritebackSlot],
) -> Result<(), EvalHeapError> {
    if slots.len() != plan.writebacks.len() {
        return Err(
            EvalHeapError::CollectorPollHeapFieldWritebackSlotLengthMismatch {
                expected: plan.writebacks.len(),
                actual: slots.len(),
            },
        );
    }

    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter()) {
        if slot.validation_object() != writeback.validation_object()
            || slot.writeback_object() != writeback.writeback_object()
        {
            return Err(
                EvalHeapError::CollectorPollHeapFieldWritebackSlotObjectMismatch {
                    index: writeback.slot(),
                    expected_validation_object: writeback.validation_object(),
                    actual_validation_object: slot.validation_object(),
                    expected_writeback_object: writeback.writeback_object(),
                    actual_writeback_object: slot.writeback_object(),
                },
            );
        }
        if slot.field_index() != writeback.field_index() || slot.source() != writeback.source() {
            return Err(
                EvalHeapError::CollectorPollHeapFieldWritebackSlotFieldMismatch {
                    index: writeback.slot(),
                    expected_field_index: writeback.field_index(),
                    actual_field_index: slot.field_index(),
                    expected_source: writeback.source().clone(),
                    actual_source: slot.source().clone(),
                },
            );
        }
        let actual = slot.value();
        if actual != writeback.expected() {
            return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                index: writeback.slot(),
                expected: writeback.expected(),
                actual,
            });
        }
    }

    Ok(())
}

pub(super) fn apply_heap_field_writeback_slots(
    plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
) {
    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter_mut()) {
        slot.value = writeback.replacement();
    }
}

pub(super) fn object_copy_request_for_reference_writeback(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    index: usize,
    expected: ResolvedValueGeneration,
    replacement: ResolvedValueGeneration,
) -> Result<AllocationCollectorPollObjectByteCopyRequest, EvalHeapError> {
    let ResolvedValueGeneration::Heap {
        address: source, ..
    } = expected
    else {
        return Err(
            EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
                index,
                expected,
                replacement,
            },
        );
    };
    let ResolvedValueGeneration::Heap {
        address: destination,
        ..
    } = replacement
    else {
        return Err(
            EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
                index,
                expected,
                replacement,
            },
        );
    };

    object_copy_request_for_reference_writeback_address(
        object_body_plan,
        index,
        source,
        destination,
    )
    .map_err(
        |_| EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
            index,
            expected,
            replacement,
        },
    )
}

pub(super) fn object_copy_request_for_reference_writeback_address(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    index: usize,
    source: GcHeapAddress,
    destination: GcHeapAddress,
) -> Result<AllocationCollectorPollObjectByteCopyRequest, EvalHeapError> {
    object_body_plan
        .requests()
        .iter()
        .copied()
        .find(|request| request.source() == source && request.destination() == destination)
        .ok_or(
            EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
                index,
                expected: ResolvedValueGeneration::Heap {
                    address: source,
                    generation: HeapGeneration::Young,
                },
                replacement: ResolvedValueGeneration::Heap {
                    address: destination,
                    generation: HeapGeneration::Young,
                },
            },
        )
}

pub(super) fn validate_collector_poll_minor_gc_reference_writeback_direct_destination_aliases(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    for write in direct_writes {
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

/// Caller-owned mutable storage for one heap-field writeback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWritebackSlot {
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollHeapFieldWritebackSlot {
    /// Creates a caller-owned heap-field slot value for writeback application.
    pub fn new(
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        value: ResolvedValueGeneration,
    ) -> Self {
        Self {
            validation_object,
            writeback_object,
            field_index,
            source,
            value,
        }
    }

    /// Returns the heap object used to validate the copied field label.
    pub const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    /// Returns the heap object whose copied field slot is rewritten.
    pub const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    /// Returns the precise field index represented by this slot.
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// Returns the copied field source label represented by this slot.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the current heap-generation value in this slot.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// A summary of caller-owned heap fields rewritten by a writeback plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWritebackReport {
    writebacks: usize,
}

impl AllocationCollectorPollHeapFieldWritebackReport {
    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn writebacks(self) -> usize {
        self.writebacks
    }
}

/// One copied-object heap field that can be rewritten in evaluator storage.
///
/// The write targets a relocated copy of a nursery object. It deliberately does
/// not describe same-object old/permanent field writes because those require a
/// separate policy for mutating hash-consed and interior-shared records. The
/// destination object is expected to be an already-bound collector-owned scratch
/// record; this side table still cannot prove semispace ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollCopiedHeapFieldWrite {
    allocation_domain: HeapAllocationDomain,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement: ResolvedValueGeneration,
    replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    writeback_object_request: AllocationCollectorPollObjectByteCopyRequest,
}

impl AllocationCollectorPollCopiedHeapFieldWrite {
    pub(crate) fn new(
        allocation_domain: HeapAllocationDomain,
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        replacement: ResolvedValueGeneration,
        replacement_request: AllocationCollectorPollObjectByteCopyRequest,
        writeback_object_request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Self {
        Self {
            allocation_domain,
            validation_object,
            writeback_object,
            field_index,
            source,
            replacement,
            replacement_request,
            writeback_object_request,
        }
    }

    pub(super) const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    pub(super) const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    pub(super) const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    pub(super) const fn field_index(&self) -> usize {
        self.field_index
    }

    pub(super) const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    pub(super) const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }

    pub(super) const fn replacement_request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.replacement_request
    }

    pub(super) const fn writeback_object_request(
        &self,
    ) -> AllocationCollectorPollObjectByteCopyRequest {
        self.writeback_object_request
    }
}

/// A record-owned old or permanent heap field rewritten in place after minor GC.
///
/// The write targets an existing old-generation worker record or a
/// permanent-shared record. The strict direct writer accepts only promoted-old
/// replacement destinations; the combined card-table-aware writer additionally
/// accepts copied-young replacement destinations after staging a
/// remembered-set/card-table update. Shared lexical environment frame slots and
/// thunk fields remain outside this direct writer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollDirectHeapFieldWrite {
    allocation_domain: HeapAllocationDomain,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement: ResolvedValueGeneration,
    replacement_request: AllocationCollectorPollObjectByteCopyRequest,
}

impl AllocationCollectorPollDirectHeapFieldWrite {
    pub(crate) fn new(
        allocation_domain: HeapAllocationDomain,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        replacement: ResolvedValueGeneration,
        replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Self {
        Self {
            allocation_domain,
            writeback_object,
            field_index,
            source,
            replacement,
            replacement_request,
        }
    }

    pub(super) const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    pub(super) const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    pub(super) const fn field_index(&self) -> usize {
        self.field_index
    }

    pub(super) const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    pub(super) const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }

    pub(super) const fn replacement_request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.replacement_request
    }
}

/// A summary of copied-object heap fields rewritten in evaluator storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollCopiedHeapFieldWriteReport {
    fields: usize,
}

impl AllocationCollectorPollCopiedHeapFieldWriteReport {
    pub(super) fn record(&mut self) {
        self.fields = self.fields.saturating_add(1);
    }

    /// Returns the number of copied heap fields rewritten.
    pub(crate) const fn fields(self) -> usize {
        self.fields
    }
}

/// A summary of direct old-generation heap fields rewritten in evaluator storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollDirectHeapFieldWriteReport {
    fields: usize,
}

impl AllocationCollectorPollDirectHeapFieldWriteReport {
    pub(super) fn record(&mut self) {
        self.fields = self.fields.saturating_add(1);
    }

    /// Returns the number of direct heap fields rewritten.
    pub(crate) const fn fields(self) -> usize {
        self.fields
    }
}

/// Caller-owned buffers for applying an allocation-poll minor-GC commit plan.
pub struct AllocationCollectorPollMinorGcCommitBuffers<'a, 'bytes> {
    pub(super) object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
    pub(super) forwarding_slots: &'a mut [MinorGcForwardingSlot],
    pub(super) references: &'a mut [ResolvedValueGeneration],
    pub(super) remembered_set: &'a mut RememberedSet,
    pub(super) card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> AllocationCollectorPollMinorGcCommitBuffers<'a, 'bytes> {
    /// Creates caller-owned buffers for an allocation-poll commit application.
    pub fn new(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates caller-owned buffers plus a card table to clear after commit.
    pub fn with_card_table(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}

/// Caller-owned destination storage and metadata for an allocation-poll commit plan.
pub struct AllocationCollectorPollMinorGcOwnedCommitBuffers<'a, 'bytes> {
    pub(super) destination_storage: &'a mut MinorGcOwnedDestinationStorage,
    pub(super) source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
    pub(super) forwarding_slots: &'a mut [MinorGcForwardingSlot],
    pub(super) references: &'a mut [ResolvedValueGeneration],
    pub(super) remembered_set: &'a mut RememberedSet,
    pub(super) card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> AllocationCollectorPollMinorGcOwnedCommitBuffers<'a, 'bytes> {
    /// Creates owned destination storage and metadata for an allocation-poll commit.
    pub fn new(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates owned destination storage and metadata plus a card table to clear.
    pub fn with_card_table(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}
