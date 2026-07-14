//! Forwarding-install and root/reference writeback plans, slots, and
//! reports, plus their slot validators.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

/// A summary of live evaluator heap forwarding values installed for minor GC.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollForwardingInstallReport {
    pub(super) forwarding_pointers: usize,
}

impl AllocationCollectorPollForwardingInstallReport {
    /// Returns the number of evaluator heap forwarding values installed.
    pub const fn forwarding_pointers(self) -> usize {
        self.forwarding_pointers
    }
}

/// One live side-table forwarding value installed on an evaluator heap record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollForwardingValue {
    source: GcHeapAddress,
    forwarded_value: ResolvedValueGeneration,
}

impl AllocationCollectorPollForwardingValue {
    pub(super) const fn new(
        source: GcHeapAddress,
        forwarded_value: ResolvedValueGeneration,
    ) -> Self {
        Self {
            source,
            forwarded_value,
        }
    }

    /// Returns the from-space object that owns the forwarding cell.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the forwarding metadata installed for the source object.
    pub const fn forwarded_value(self) -> ResolvedValueGeneration {
        self.forwarded_value
    }
}

/// One root-backed reference that must be rewritten after minor GC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWriteback {
    slot: usize,
    source: EvalRootSource,
    expected: ResolvedValueGeneration,
    expected_tag: ValueTag,
    replacement: ResolvedValueGeneration,
    replacement_tag: ValueTag,
}

impl AllocationCollectorPollRootWriteback {
    pub(super) fn new(
        slot: usize,
        source: EvalRootSource,
        expected: ResolvedValueGeneration,
        expected_tag: ValueTag,
        replacement: ResolvedValueGeneration,
        replacement_tag: ValueTag,
    ) -> Self {
        Self {
            slot,
            source,
            expected,
            expected_tag,
            replacement,
            replacement_tag,
        }
    }

    /// Returns the copied reference slot that produced this writeback.
    pub const fn slot(&self) -> usize {
        self.slot
    }

    /// Returns the copied tree-walk/JIT root source to rewrite.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the young from-space value expected in the root slot.
    pub const fn expected(&self) -> ResolvedValueGeneration {
        self.expected
    }

    /// Returns the heap tag expected in the root slot.
    pub const fn expected_tag(&self) -> ValueTag {
        self.expected_tag
    }

    /// Returns the relocated value that must replace [`Self::expected`].
    pub const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }

    /// Returns the heap tag for [`Self::replacement`].
    ///
    /// Minor-GC relocation preserves the object type, so this tag matches
    /// [`Self::expected_tag`]. It is carried explicitly for future live
    /// tree-walk/JIT root-slot mutation, where address plus generation is not
    /// enough to reconstruct a typed [`Value`].
    pub const fn replacement_tag(&self) -> ValueTag {
        self.replacement_tag
    }

    /// Reconstructs the typed young from-space value expected in the root slot.
    ///
    /// This validates the value word's tag/address shape only. It does not
    /// prove that the source object remains live in an [`EvalHeap`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the expected value is no longer heap-backed
    /// metadata or if its address is not valid for a typed evaluator heap
    /// pointer.
    pub fn expected_value(&self) -> Result<Value, EvalHeapError> {
        value_for_resolved_generation(self.expected_tag, self.expected)
    }

    /// Reconstructs the typed relocated value that should replace the root slot.
    ///
    /// This validates the value word's tag/address shape only. It does not bind
    /// the value to live semispace storage or install it into a root slot.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the replacement value is no longer
    /// heap-backed metadata or if its address is not valid for a typed evaluator
    /// heap pointer.
    pub fn replacement_value(&self) -> Result<Value, EvalHeapError> {
        value_for_resolved_generation(self.replacement_tag, self.replacement)
    }
}

/// Root writebacks derived from an allocation-poll minor-GC commit plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWritebackPlan {
    writebacks: Vec<AllocationCollectorPollRootWriteback>,
}

impl AllocationCollectorPollRootWritebackPlan {
    pub(super) fn new(writebacks: Vec<AllocationCollectorPollRootWriteback>) -> Self {
        Self { writebacks }
    }

    /// Returns planned root writebacks in reference-rewrite order.
    pub fn writebacks(&self) -> &[AllocationCollectorPollRootWriteback] {
        &self.writebacks
    }

    /// Returns planned writebacks for compiled stack-map roots.
    ///
    /// The iterator preserves reference-rewrite order and filters only
    /// [`EvalRootSource::StackMap`] entries. It is metadata for a later JIT
    /// stack-map writer; applying the returned entries still requires
    /// caller-owned slots and does not mutate compiled frames.
    pub fn stack_map_writebacks(
        &self,
    ) -> impl Iterator<Item = &AllocationCollectorPollRootWriteback> {
        self.writebacks
            .iter()
            .filter(|writeback| matches!(writeback.source(), EvalRootSource::StackMap { .. }))
    }

    /// Returns the number of compiled stack-map root writebacks.
    pub fn stack_map_writeback_count(&self) -> usize {
        self.stack_map_writebacks().count()
    }

    /// Returns the number of root writebacks.
    pub fn len(&self) -> usize {
        self.writebacks.len()
    }

    /// Returns whether there are no root writebacks.
    pub fn is_empty(&self) -> bool {
        self.writebacks.is_empty()
    }

    /// Applies planned root writebacks to caller-owned root slots.
    ///
    /// The supplied slots must match this plan's root writeback count and order.
    /// Each slot must name the copied root source and still contain the expected
    /// young from-space value. The method validates every slot before rewriting
    /// any slot, so validation failures leave the caller-owned buffer unchanged.
    /// This mutates only the supplied buffer; it does not bind to active
    /// tree-walk value stacks, frames, import caches, or JIT stack maps.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the supplied slot count differs from the
    /// plan, if a slot names a different copied root source, or if a slot no
    /// longer contains the expected young from-space value.
    pub fn apply_to_slots(
        &self,
        slots: &mut [AllocationCollectorPollRootWritebackSlot],
    ) -> Result<AllocationCollectorPollRootWritebackReport, EvalHeapError> {
        validate_root_writeback_slots(self, slots)?;
        apply_root_writeback_slots(self, slots);

        Ok(AllocationCollectorPollRootWritebackReport {
            writebacks: self.writebacks.len(),
        })
    }

    /// Applies planned root writebacks to caller-owned typed value slots.
    ///
    /// The supplied slots must match this plan's root writeback count and order.
    /// Each slot must name the copied root source and still contain the exact
    /// raw [`Value`] reconstructed by [`AllocationCollectorPollRootWriteback::expected_value`].
    /// The method validates every slot before rewriting any slot, so validation
    /// failures leave the caller-owned buffer unchanged. This mutates only the
    /// supplied buffer; it does not bind to active tree-walk value stacks,
    /// frames, import caches, or JIT stack maps.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the supplied slot count differs from the
    /// plan, if a slot names a different copied root source, if a planned
    /// expected or replacement value cannot be reconstructed from root-writeback
    /// metadata, or if a caller-owned value no longer contains the expected raw
    /// value.
    pub fn apply_to_value_slots(
        &self,
        slots: &mut [AllocationCollectorPollRootValueWritebackSlot],
    ) -> Result<AllocationCollectorPollRootWritebackReport, EvalHeapError> {
        validate_root_value_writeback_slots(self, slots)?;
        apply_root_value_writeback_slots(self, slots)?;

        Ok(AllocationCollectorPollRootWritebackReport {
            writebacks: self.writebacks.len(),
        })
    }
}

pub(super) fn validate_root_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<(), EvalHeapError> {
    if slots.len() != plan.writebacks.len() {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected: plan.writebacks.len(),
                actual: slots.len(),
            },
        );
    }

    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter()) {
        if slot.source() != writeback.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index: writeback.slot(),
                expected: writeback.source().clone(),
                actual: slot.source().clone(),
            });
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

pub(super) fn apply_root_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &mut [AllocationCollectorPollRootWritebackSlot],
) {
    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter_mut()) {
        slot.value = writeback.replacement();
    }
}

pub(super) fn validate_root_value_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &[AllocationCollectorPollRootValueWritebackSlot],
) -> Result<(), EvalHeapError> {
    if slots.len() != plan.writebacks.len() {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected: plan.writebacks.len(),
                actual: slots.len(),
            },
        );
    }

    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter()) {
        if slot.source() != writeback.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index: writeback.slot(),
                expected: writeback.source().clone(),
                actual: slot.source().clone(),
            });
        }
        let expected = writeback.expected_value()?;
        let actual = slot.value();
        if !actual.raw_eq(expected) {
            return Err(root_value_writeback_slot_mismatch(
                writeback.slot(),
                expected,
                actual,
            ));
        }
        let _ = writeback.replacement_value()?;
    }

    Ok(())
}

pub(super) fn apply_root_value_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &mut [AllocationCollectorPollRootValueWritebackSlot],
) -> Result<(), EvalHeapError> {
    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter_mut()) {
        slot.value = writeback.replacement_value()?;
    }
    Ok(())
}

pub(super) fn root_value_writeback_slot_mismatch(
    index: usize,
    expected: Value,
    actual: Value,
) -> EvalHeapError {
    EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
        index,
        expected_tag: expected.tag(),
        expected_payload: expected.payload_bits(),
        actual_tag: actual.tag(),
        actual_payload: actual.payload_bits(),
    }
}

/// Caller-owned mutable storage for one root writeback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWritebackSlot {
    source: EvalRootSource,
    pub(super) value: ResolvedValueGeneration,
}

impl AllocationCollectorPollRootWritebackSlot {
    /// Creates a caller-owned root slot value for writeback application.
    pub fn new(source: EvalRootSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the copied tree-walk/JIT root source represented by this slot.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the current heap-generation value in this slot.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// Caller-owned mutable typed storage for one root writeback.
///
/// Equality compares copied root sources and raw [`Value`] representations; it
/// is not evaluator-level Nix semantic equality.
#[derive(Clone, Debug)]
pub struct AllocationCollectorPollRootValueWritebackSlot {
    source: EvalRootSource,
    pub(super) value: Value,
}

impl AllocationCollectorPollRootValueWritebackSlot {
    /// Creates a caller-owned typed root slot for writeback application.
    pub fn new(source: EvalRootSource, value: Value) -> Self {
        Self { source, value }
    }

    /// Returns the copied tree-walk/JIT root source represented by this slot.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the current typed evaluator value in this slot.
    pub const fn value(&self) -> Value {
        self.value
    }
}

impl PartialEq for AllocationCollectorPollRootValueWritebackSlot {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.value.raw_eq(other.value)
    }
}

impl Eq for AllocationCollectorPollRootValueWritebackSlot {}

/// A summary of caller-owned root slots rewritten by a writeback plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWritebackReport {
    pub(super) writebacks: usize,
}

impl AllocationCollectorPollRootWritebackReport {
    /// Returns the number of caller-owned root slots rewritten.
    pub const fn writebacks(self) -> usize {
        self.writebacks
    }
}

/// Complete root and heap-field reference writebacks for one minor-GC commit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollReferenceWritebackPlan {
    root_writebacks: AllocationCollectorPollRootWritebackPlan,
    heap_field_writebacks: AllocationCollectorPollHeapFieldWritebackPlan,
}

impl AllocationCollectorPollReferenceWritebackPlan {
    pub(super) fn new(
        root_writebacks: AllocationCollectorPollRootWritebackPlan,
        heap_field_writebacks: AllocationCollectorPollHeapFieldWritebackPlan,
    ) -> Self {
        Self {
            root_writebacks,
            heap_field_writebacks,
        }
    }

    /// Returns writebacks for externally owned root slots.
    pub const fn root_writebacks(&self) -> &AllocationCollectorPollRootWritebackPlan {
        &self.root_writebacks
    }

    /// Returns writebacks for evaluator-owned heap fields.
    pub const fn heap_field_writebacks(&self) -> &AllocationCollectorPollHeapFieldWritebackPlan {
        &self.heap_field_writebacks
    }

    /// Returns the total number of planned reference writebacks.
    pub fn len(&self) -> usize {
        self.root_writebacks.len() + self.heap_field_writebacks.len()
    }

    /// Returns whether there are no reference writebacks.
    pub fn is_empty(&self) -> bool {
        self.root_writebacks.is_empty() && self.heap_field_writebacks.is_empty()
    }

    /// Applies root and heap-field writebacks to caller-owned slot buffers.
    ///
    /// Both partitions are validated before either partition is rewritten. This
    /// prevents a stale heap-field slot from partially rewriting root slots, and
    /// vice versa. The method mutates only the supplied buffers; it does not bind
    /// to active tree-walk/JIT roots, live evaluator object fields, object bytes,
    /// object headers, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if either caller-owned slot buffer no longer
    /// matches its derived writeback plan.
    pub fn apply_to_slots(
        &self,
        root_slots: &mut [AllocationCollectorPollRootWritebackSlot],
        heap_field_slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
    ) -> Result<AllocationCollectorPollReferenceWritebackReport, EvalHeapError> {
        validate_root_writeback_slots(&self.root_writebacks, root_slots)?;
        validate_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots)?;

        apply_root_writeback_slots(&self.root_writebacks, root_slots);
        apply_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots);

        Ok(AllocationCollectorPollReferenceWritebackReport {
            root_writebacks: self.root_writebacks.len(),
            heap_field_writebacks: self.heap_field_writebacks.len(),
        })
    }

    /// Applies typed root and heap-field writebacks to caller-owned buffers.
    ///
    /// This is the typed-root variant of [`Self::apply_to_slots`]. Root slots
    /// contain concrete [`Value`] handles so tree-walk callers can preserve heap
    /// tags while heap-field slots continue to carry generation-style metadata.
    /// Both partitions are validated before either partition is rewritten.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if either caller-owned slot buffer no longer
    /// matches its derived writeback plan, or if a planned root replacement
    /// cannot be reconstructed as a typed [`Value`].
    pub fn apply_to_value_and_heap_field_slots(
        &self,
        root_slots: &mut [AllocationCollectorPollRootValueWritebackSlot],
        heap_field_slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
    ) -> Result<AllocationCollectorPollReferenceWritebackReport, EvalHeapError> {
        validate_root_value_writeback_slots(&self.root_writebacks, root_slots)?;
        validate_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots)?;

        apply_root_value_writeback_slots(&self.root_writebacks, root_slots)?;
        apply_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots);

        Ok(AllocationCollectorPollReferenceWritebackReport {
            root_writebacks: self.root_writebacks.len(),
            heap_field_writebacks: self.heap_field_writebacks.len(),
        })
    }
}

/// A summary of caller-owned reference slots rewritten by a combined plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollReferenceWritebackReport {
    root_writebacks: usize,
    heap_field_writebacks: usize,
}

impl AllocationCollectorPollReferenceWritebackReport {
    /// Returns the number of caller-owned root slots rewritten.
    pub const fn root_writebacks(self) -> usize {
        self.root_writebacks
    }

    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn heap_field_writebacks(self) -> usize {
        self.heap_field_writebacks
    }

    /// Returns the total number of caller-owned reference slots rewritten.
    pub const fn writebacks(self) -> usize {
        self.root_writebacks + self.heap_field_writebacks
    }
}

/// A caller-supplied current value for one copied root reference slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollRootReferenceValue {
    source: EvalRootSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollRootReferenceValue {
    /// Creates a current root value for the copied root slot named by `source`.
    pub fn new(source: EvalRootSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the copied root source this value belongs to.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the current value read from the root source.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}
