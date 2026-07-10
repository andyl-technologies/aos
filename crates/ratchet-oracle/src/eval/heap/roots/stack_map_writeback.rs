//! Transactional mutation of caller-bound JIT stack-map slots.
//!
//! Minor-GC root plans mix tree-walk roots with compiled-frame roots. The JIT
//! runtime binds the latter to live stack/register spill storage, then this
//! module validates every binding before publishing any relocated value.

use super::*;

impl AllocationCollectorPollRootWritebackPlan {
    /// Applies compiled-frame writebacks to caller-owned generation slots.
    ///
    /// `slots` contains only [`EvalRootSource::StackMap`] bindings, in the
    /// order returned by [`Self::stack_map_writebacks`]. The method validates
    /// the complete buffer before mutation. It does not locate a compiled
    /// frame or interpret machine registers; the JIT runtime owns that binding.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the stack-map slot count differs from the
    /// plan, a binding names a different source, or a binding no longer holds
    /// the planned from-space value.
    pub fn apply_to_stack_map_slots(
        &self,
        slots: &mut [AllocationCollectorPollRootWritebackSlot],
    ) -> Result<AllocationCollectorPollRootWritebackReport, EvalHeapError> {
        validate_stack_map_slots(self, slots)?;
        for (writeback, slot) in self.stack_map_writebacks().zip(slots.iter_mut()) {
            slot.value = writeback.replacement();
        }
        Ok(AllocationCollectorPollRootWritebackReport {
            writebacks: slots.len(),
        })
    }

    /// Applies compiled-frame writebacks to caller-owned typed value slots.
    ///
    /// `slots` contains only [`EvalRootSource::StackMap`] bindings, in the
    /// order returned by [`Self::stack_map_writebacks`]. Expected and
    /// replacement value words for every binding are validated before the
    /// first mutation. The JIT runtime remains responsible for spilling live
    /// values and writing the updated words back to their physical locations.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the stack-map slot count differs from the
    /// plan, a binding names a different source, a binding no longer holds the
    /// planned from-space value, or typed value reconstruction fails.
    pub fn apply_to_stack_map_value_slots(
        &self,
        slots: &mut [AllocationCollectorPollRootValueWritebackSlot],
    ) -> Result<AllocationCollectorPollRootWritebackReport, EvalHeapError> {
        validate_stack_map_value_slots(self, slots)?;
        for (writeback, slot) in self.stack_map_writebacks().zip(slots.iter_mut()) {
            slot.value = writeback.replacement_value()?;
        }
        Ok(AllocationCollectorPollRootWritebackReport {
            writebacks: slots.len(),
        })
    }
}

fn validate_stack_map_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<(), EvalHeapError> {
    let expected = plan.stack_map_writeback_count();
    if slots.len() != expected {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected,
                actual: slots.len(),
            },
        );
    }
    for (writeback, slot) in plan.stack_map_writebacks().zip(slots) {
        if slot.source() != writeback.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index: writeback.slot(),
                expected: writeback.source().clone(),
                actual: slot.source().clone(),
            });
        }
        if slot.value() != writeback.expected() {
            return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                index: writeback.slot(),
                expected: writeback.expected(),
                actual: slot.value(),
            });
        }
    }
    Ok(())
}

fn validate_stack_map_value_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &[AllocationCollectorPollRootValueWritebackSlot],
) -> Result<(), EvalHeapError> {
    let expected = plan.stack_map_writeback_count();
    if slots.len() != expected {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected,
                actual: slots.len(),
            },
        );
    }
    for (writeback, slot) in plan.stack_map_writebacks().zip(slots) {
        if slot.source() != writeback.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index: writeback.slot(),
                expected: writeback.source().clone(),
                actual: slot.source().clone(),
            });
        }
        let expected_value = writeback.expected_value()?;
        let actual = slot.value();
        if !actual.raw_eq(expected_value) {
            return Err(root_value_writeback_slot_mismatch(
                writeback.slot(),
                expected_value,
                actual,
            ));
        }
        let _ = writeback.replacement_value()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(bits: usize) -> GcHeapAddress {
        GcHeapAddress::new(bits).expect("test address is nonzero")
    }

    fn value(address_bits: usize, generation: HeapGeneration) -> ResolvedValueGeneration {
        ResolvedValueGeneration::Heap {
            address: address(address_bits),
            generation,
        }
    }

    fn stack_source(offset: i32) -> EvalRootSource {
        EvalRootSource::StackMap {
            frame: 7,
            safepoint: 11,
            slot: StackMapSlot::Stack { offset },
        }
    }

    fn writeback(
        slot: usize,
        source: EvalRootSource,
        from: usize,
        to: usize,
    ) -> AllocationCollectorPollRootWriteback {
        AllocationCollectorPollRootWriteback::new(
            slot,
            source,
            value(from, HeapGeneration::Young),
            ValueTag::Thunk,
            value(to, HeapGeneration::Old),
            ValueTag::Thunk,
        )
    }

    fn mixed_plan() -> AllocationCollectorPollRootWritebackPlan {
        AllocationCollectorPollRootWritebackPlan::new(vec![
            writeback(0, stack_source(-16), 0x1000, 0x2000),
            writeback(
                1,
                EvalRootSource::ValueStack { slot: 3 },
                0x1100,
                0x2100,
            ),
            writeback(2, stack_source(-32), 0x1200, 0x2200),
        ])
    }

    #[test]
    fn generation_writer_filters_non_stack_map_roots() {
        let plan = mixed_plan();
        let mut slots = [
            AllocationCollectorPollRootWritebackSlot::new(
                stack_source(-16),
                value(0x1000, HeapGeneration::Young),
            ),
            AllocationCollectorPollRootWritebackSlot::new(
                stack_source(-32),
                value(0x1200, HeapGeneration::Young),
            ),
        ];

        let report = plan
            .apply_to_stack_map_slots(&mut slots)
            .expect("stack-map slots rewrite");

        assert_eq!(report.writebacks(), 2);
        assert_eq!(slots[0].value(), value(0x2000, HeapGeneration::Old));
        assert_eq!(slots[1].value(), value(0x2200, HeapGeneration::Old));
    }

    #[test]
    fn typed_writer_validates_every_binding_before_mutation() {
        let plan = mixed_plan();
        let first = plan.writebacks()[0]
            .expected_value()
            .expect("first expected value builds");
        let second = plan.writebacks()[2]
            .expected_value()
            .expect("second expected value builds");
        let mut slots = [
            AllocationCollectorPollRootValueWritebackSlot::new(stack_source(-16), first),
            AllocationCollectorPollRootValueWritebackSlot::new(stack_source(-24), second),
        ];
        let unchanged = slots.clone();

        assert!(
            plan.apply_to_stack_map_value_slots(&mut slots).is_err(),
            "wrong second physical binding must reject"
        );
        assert_eq!(slots, unchanged);

        slots[1] =
            AllocationCollectorPollRootValueWritebackSlot::new(stack_source(-32), second);
        let report = plan
            .apply_to_stack_map_value_slots(&mut slots)
            .expect("typed stack-map slots rewrite");
        assert_eq!(report.writebacks(), 2);
        assert!(
            slots[0].value().raw_eq(
                plan.writebacks()[0]
                    .replacement_value()
                    .expect("first replacement builds")
            )
        );
        assert!(
            slots[1].value().raw_eq(
                plan.writebacks()[2]
                    .replacement_value()
                    .expect("second replacement builds")
            )
        );
    }
}
