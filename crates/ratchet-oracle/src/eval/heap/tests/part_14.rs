//! Evaluator-heap unit tests, part 14 of 16 (RFC-0007 §2 split, #9).
//!
//! Move-only item-boundary split of the `tests.rs` inline body; each
//! test keeps its `#[cfg]`/doc prefix. No test changed.

#![allow(unused_imports)]

use super::super::*;
use super::*;


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_card_table_plan_rejects_clean_unremembered_source_card() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, permanent_parent)
        .expect("permanent parent root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let card_table = GcCardTable::default();

    let error = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("clean unremembered source card is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollRememberedEdge {
            source_address: gc_address(permanent_parent),
            target_address: gc_address(child),
        }
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_card_table_rescan_publishes_dirty_survivor_edge() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();
    card_table
        .mark_source(gc_address(permanent_parent))
        .expect("permanent parent card marks");

    let planned = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("dirty card admits already-surviving unremembered edge");

    assert_eq!(planned.remembered_set(), &remembered_set);
    assert_eq!(
        planned
            .card_table()
            .expect("card-table-aware plan records dirty cards")
            .dirty_cards(),
        card_table.dirty_cards()
    );
    let old_parent_fields = planned
        .old_fields()
        .iter()
        .find(|fields| fields.address() == gc_address(permanent_parent))
        .expect("permanent parent fields are captured");
    assert_eq!(old_parent_fields.generation(), HeapGeneration::Permanent);
    assert_eq!(old_parent_fields.fields().len(), 1);
    assert_eq!(
        old_parent_fields.fields()[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        old_parent_fields.fields()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(planned.reference_slots().len(), 2);

    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan includes dirty old-field rescan");
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();

    assert!(commit.commit_plan().remembered_set_refresh().is_empty());
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[RememberedEdge::new(
            gc_address(permanent_parent),
            child_destination,
        )]
    );
    let mut published_remembered_set = remembered_set.clone();
    commit
        .commit_plan()
        .clone()
        .publish_next_remembered_set(&mut published_remembered_set)
        .expect("empty source remembered set publishes rescan edge");
    assert_eq!(
        published_remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(permanent_parent),
            child_destination,
        )]
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_writeback_plans_filter_mixed_root_and_heap_rewrites() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(
            gc_address(permanent_parent),
            gc_address(child),
        ))
        .expect("remembered edge records");
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();

    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 1);
    assert_eq!(root_writeback_plan.writebacks()[0].slot(), 0);
    assert_eq!(
        root_writeback_plan.writebacks()[0].source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(
        root_writeback_plan.writebacks()[0].replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let heap_writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives");
    assert_eq!(heap_writeback_plan.len(), 1);
    assert_eq!(heap_writeback_plan.writebacks()[0].slot(), 1);
    assert_eq!(
        heap_writeback_plan.writebacks()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        heap_writeback_plan.writebacks()[0].replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let reference_writeback_plan = heap
        .collector_poll_minor_gc_reference_writeback_plan(&commit)
        .expect("combined reference writeback plan derives");
    assert_eq!(reference_writeback_plan.len(), 2);
    assert!(!reference_writeback_plan.is_empty());
    assert_eq!(reference_writeback_plan.root_writebacks().len(), 1);
    assert_eq!(
        reference_writeback_plan.root_writebacks().writebacks()[0].slot(),
        0
    );
    assert_eq!(reference_writeback_plan.heap_field_writebacks().len(), 1);
    assert_eq!(
        reference_writeback_plan
            .heap_field_writebacks()
            .writebacks()[0]
            .slot(),
        1
    );

    let mut stale_root_slots = [AllocationCollectorPollRootWritebackSlot::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let mut stale_heap_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(permanent_parent),
        gc_address(permanent_parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Inline,
    )];
    let unchanged_stale_root_slots = stale_root_slots.clone();
    let unchanged_stale_heap_slots = stale_heap_slots.clone();
    assert_eq!(
        reference_writeback_plan
            .apply_to_slots(&mut stale_root_slots, &mut stale_heap_slots)
            .expect_err("stale heap field rejects combined writeback"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_root_slots, unchanged_stale_root_slots);
    assert_eq!(stale_heap_slots, unchanged_stale_heap_slots);

    let mut stale_root_slots = [AllocationCollectorPollRootWritebackSlot::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Inline,
    )];
    let mut stale_heap_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(permanent_parent),
        gc_address(permanent_parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let unchanged_stale_root_slots = stale_root_slots.clone();
    let unchanged_stale_heap_slots = stale_heap_slots.clone();
    assert_eq!(
        reference_writeback_plan
            .apply_to_slots(&mut stale_root_slots, &mut stale_heap_slots)
            .expect_err("stale root rejects combined writeback"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_root_slots, unchanged_stale_root_slots);
    assert_eq!(stale_heap_slots, unchanged_stale_heap_slots);

    let mut root_slots = [AllocationCollectorPollRootWritebackSlot::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let mut heap_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(permanent_parent),
        gc_address(permanent_parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let report = reference_writeback_plan
        .apply_to_slots(&mut root_slots, &mut heap_slots)
        .expect("combined reference writebacks apply");
    assert_eq!(report.root_writebacks(), 1);
    assert_eq!(report.heap_field_writebacks(), 1);
    assert_eq!(report.writebacks(), 2);
    assert_eq!(
        root_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let reference_buffer = heap
        .collector_poll_minor_gc_reference_buffer(
            &commit,
            &[AllocationCollectorPollRootReferenceValue::new(
                EvalRootSource::ValueStack { slot: 0 },
                ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Young,
                },
            )],
        )
        .expect("mixed reference buffer derives");
    assert_eq!(
        reference_buffer,
        vec![
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ]
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_root_writeback_plan_applies_caller_owned_slots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("second thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, first)
        .expect("first root records");
    roots
        .try_push_value_stack(1, second)
        .expect("second root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 2);
    let first_destination = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(first))
        .expect("first survivor copy is planned")
        .destination();
    let second_destination = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(second))
        .expect("second survivor copy is planned")
        .destination();

    let mut no_slots = Vec::new();
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut no_slots)
            .expect_err("short root writeback buffer rejects"),
        EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
            expected: 2,
            actual: 0,
        }
    );

    let mut no_value_slots = Vec::new();
    assert_eq!(
        root_writeback_plan
            .apply_to_value_slots(&mut no_value_slots)
            .expect_err("short typed root writeback buffer rejects"),
        EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
            expected: 2,
            actual: 0,
        }
    );

    let mut stale_slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            ResolvedValueGeneration::Inline,
        ),
    ];
    let unchanged_stale_slots = stale_slots.clone();
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut stale_slots)
            .expect_err("stale second root rejects"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_slots, unchanged_stale_slots);

    let mut wrong_source_slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 2 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut wrong_source_slots)
            .expect_err("wrong root source rejects"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 0,
            expected: EvalRootSource::ValueStack { slot: 0 },
            actual: EvalRootSource::ValueStack { slot: 2 },
        }
    );

    let mut later_wrong_source_slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 2 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    let unchanged_later_wrong_source_slots = later_wrong_source_slots.clone();
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut later_wrong_source_slots)
            .expect_err("later wrong root source rejects"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 1,
            expected: EvalRootSource::ValueStack { slot: 1 },
            actual: EvalRootSource::ValueStack { slot: 2 },
        }
    );
    assert_eq!(later_wrong_source_slots, unchanged_later_wrong_source_slots);

    let mut slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    let report = root_writeback_plan
        .apply_to_slots(&mut slots)
        .expect("root writebacks apply");
    assert_eq!(report.writebacks(), 2);
    assert_eq!(
        slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: first_destination,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        slots[1].value(),
        ResolvedValueGeneration::Heap {
            address: second_destination,
            generation: HeapGeneration::Young,
        }
    );

    let mut later_wrong_source_value_slots = [
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            first,
        ),
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 2 },
            second,
        ),
    ];
    let unchanged_later_wrong_source_value_slots = later_wrong_source_value_slots.clone();
    assert_eq!(
        root_writeback_plan
            .apply_to_value_slots(&mut later_wrong_source_value_slots)
            .expect_err("later wrong typed root source rejects"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 1,
            expected: EvalRootSource::ValueStack { slot: 1 },
            actual: EvalRootSource::ValueStack { slot: 2 },
        }
    );
    assert_eq!(
        later_wrong_source_value_slots,
        unchanged_later_wrong_source_value_slots
    );

    let mut stale_value_slots = [
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            first,
        ),
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            first,
        ),
    ];
    let unchanged_stale_value_slots = stale_value_slots.clone();
    let expected_second_value = root_writeback_plan.writebacks()[1]
        .expected_value()
        .expect("second expected value rebuilds");
    assert_eq!(
        root_writeback_plan
            .apply_to_value_slots(&mut stale_value_slots)
            .expect_err("stale typed second root rejects"),
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
            index: 1,
            expected_tag: expected_second_value.tag(),
            expected_payload: expected_second_value.payload_bits(),
            actual_tag: first.tag(),
            actual_payload: first.payload_bits(),
        }
    );
    assert_eq!(stale_value_slots, unchanged_stale_value_slots);

    let mut value_slots = root_writeback_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollRootValueWritebackSlot::new(
                writeback.source().clone(),
                writeback
                    .expected_value()
                    .expect("expected typed value rebuilds"),
            )
        })
        .collect::<Vec<_>>();
    let value_report = root_writeback_plan
        .apply_to_value_slots(&mut value_slots)
        .expect("typed root writebacks apply");
    assert_eq!(value_report.writebacks(), 2);
    for (slot, writeback) in value_slots.iter().zip(root_writeback_plan.writebacks()) {
        assert!(
            slot.value().raw_eq(
                writeback
                    .replacement_value()
                    .expect("replacement typed value rebuilds")
            )
        );
    }
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_root_writeback_plan_filters_stack_map_roots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let stack_value = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("stack-map thunk allocates");
    let register_value = heap
        .alloc_thunk(EvalThunk::new(IrId::new(13)))
        .expect("register thunk allocates");
    let value_stack_value = heap
        .alloc_thunk(EvalThunk::new(IrId::new(17)))
        .expect("value-stack thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_stack_map(44, 7, StackMapSlot::Stack { offset: -24 }, stack_value)
        .expect("stack-map stack root records");
    roots
        .try_push_stack_map(
            44,
            7,
            StackMapSlot::Register { dwarf_reg: 3 },
            register_value,
        )
        .expect("stack-map register root records");
    roots
        .try_push_value_stack(9, value_stack_value)
        .expect("value-stack root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");

    assert_eq!(root_writeback_plan.len(), 3);
    assert_eq!(root_writeback_plan.stack_map_writeback_count(), 2);
    assert_eq!(
        root_writeback_plan
            .stack_map_writebacks()
            .map(AllocationCollectorPollRootWriteback::slot)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        root_writeback_plan.writebacks()[0].source(),
        &EvalRootSource::StackMap {
            frame: 44,
            safepoint: 7,
            slot: StackMapSlot::Stack { offset: -24 },
        }
    );
    assert_eq!(
        root_writeback_plan.writebacks()[1].source(),
        &EvalRootSource::StackMap {
            frame: 44,
            safepoint: 7,
            slot: StackMapSlot::Register { dwarf_reg: 3 },
        }
    );
    assert_eq!(
        root_writeback_plan.writebacks()[2].source(),
        &EvalRootSource::ValueStack { slot: 9 }
    );
    for writeback in root_writeback_plan.writebacks() {
        assert_eq!(writeback.expected_tag(), ValueTag::Thunk);
        assert_eq!(writeback.replacement_tag(), ValueTag::Thunk);
        let ResolvedValueGeneration::Heap {
            address: expected_address,
            ..
        } = writeback.expected()
        else {
            panic!("expected root writeback value should be heap-backed");
        };
        let ResolvedValueGeneration::Heap {
            address: replacement_address,
            ..
        } = writeback.replacement()
        else {
            panic!("replacement root writeback value should be heap-backed");
        };
        let expected_value = writeback.expected_value().expect("expected value rebuilds");
        let replacement_value = writeback
            .replacement_value()
            .expect("replacement value rebuilds");
        assert!(
            expected_value.raw_eq(
                Value::heap(
                    ValueTag::Thunk,
                    NonNull::new(expected_address.address_bits() as *mut HeapObject)
                        .expect("expected address is non-null"),
                )
                .expect("expected raw value rebuilds")
            )
        );
        assert!(
            replacement_value.raw_eq(
                Value::heap(
                    ValueTag::Thunk,
                    NonNull::new(replacement_address.address_bits() as *mut HeapObject)
                        .expect("replacement address is non-null"),
                )
                .expect("replacement raw value rebuilds")
            )
        );
    }

    let mut slots = root_writeback_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollRootWritebackSlot::new(
                writeback.source().clone(),
                writeback.expected(),
            )
        })
        .collect::<Vec<_>>();
    let report = root_writeback_plan
        .apply_to_slots(&mut slots)
        .expect("root writebacks apply");
    assert_eq!(report.writebacks(), 3);
    for (slot, writeback) in slots.iter().zip(root_writeback_plan.writebacks()) {
        assert_eq!(slot.source(), writeback.source());
        assert_eq!(slot.value(), writeback.replacement());
    }
}
