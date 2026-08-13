//! Evaluator-heap unit tests, part 15 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_plan_expands_remembered_edge_to_concrete_source_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child, child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");

    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");

    assert_eq!(planned.reference_slots().len(), 3);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: RememberedEdge::new(gc_address(root), gc_address(child)),
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[2].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: RememberedEdge::new(gc_address(root), gc_address(child)),
            field_index: 1,
            source: HeapEdgeSource::ListElement { index: 1 },
        }
    );

    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let relocation_plan = destinations
        .relocation_destinations()
        .relocation_plan(planned.plan())
        .expect("relocation plan rebuilds");
    let rewrite_plan = planned
        .reference_rewrite_plan(&relocation_plan)
        .expect("reference rewrite plan builds");
    assert_eq!(rewrite_plan.rewrites().len(), 2);
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 1);
    assert_eq!(rewrite_plan.rewrites()[1].slot(), 2);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_plan_rejects_stale_remembered_edge_without_source_field() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    // A permanent record-backed value with no heap field pointing at the
    // child (strings are flat since FV-1, so a list stands in).
    let root = heap
        .alloc_list(NixList::new(vec![Value::int(3)]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");

    assert_eq!(
        heap.plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("stale remembered edge is rejected"),
        EvalHeapError::StaleCollectorPollRememberedEdge {
            source_address: gc_address(root),
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
fn collector_poll_minor_gc_heap_field_reference_buffer_reads_remembered_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
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

    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 0);
    assert!(root_writeback_plan.is_empty());
    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_reference_buffer(&commit)
            .expect("heap-field references derive"),
        vec![ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }]
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();
    let mut short_slots = Vec::new();
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut short_slots)
            .expect_err("short heap-field writeback buffer rejects"),
        EvalHeapError::CollectorPollHeapFieldWritebackSlotLengthMismatch {
            expected: 1,
            actual: 0,
        }
    );
    let mut object_mismatch_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(child),
        gc_address(root),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut object_mismatch_slots)
            .expect_err("wrong heap-field objects reject"),
        EvalHeapError::CollectorPollHeapFieldWritebackSlotObjectMismatch {
            index: 0,
            expected_validation_object: gc_address(root),
            actual_validation_object: gc_address(child),
            expected_writeback_object: gc_address(root),
            actual_writeback_object: gc_address(root),
        }
    );
    let mut field_mismatch_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(root),
        gc_address(root),
        1,
        HeapEdgeSource::ListElement { index: 1 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut field_mismatch_slots)
            .expect_err("wrong heap-field label rejects"),
        EvalHeapError::CollectorPollHeapFieldWritebackSlotFieldMismatch {
            index: 0,
            expected_field_index: 0,
            actual_field_index: 1,
            expected_source: HeapEdgeSource::ListElement { index: 0 },
            actual_source: HeapEdgeSource::ListElement { index: 1 },
        }
    );
    let mut stale_value_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(root),
        gc_address(root),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Inline,
    )];
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut stale_value_slots)
            .expect_err("stale heap-field value rejects"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );

    let mut slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(root),
        gc_address(root),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let report = writeback_plan
        .apply_to_slots(&mut slots)
        .expect("heap-field writebacks apply");
    assert_eq!(report.writebacks(), 1);
    assert_eq!(
        slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
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
fn collector_poll_minor_gc_heap_field_writeback_plan_rejects_stale_same_label_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let sibling = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("sibling thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
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

    replace_list_record(&mut heap, root, NixList::new(vec![sibling]));

    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_writeback_plan(&commit)
            .expect_err("same-label value drift rejects writeback plan"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Heap {
                address: gc_address(sibling),
                generation: HeapGeneration::Young,
            },
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
fn collector_poll_minor_gc_heap_field_writeback_plan_uses_promoted_nursery_owner() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let grandchild = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("grandchild thunk allocates");
    let child = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(7),
            grandchild,
            IrAttrPathId::new(0),
        ))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(0),
        )
        .expect("promoting minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x3000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let child_copy = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(child))
        .expect("child survivor copy is planned");
    let grandchild_copy = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(grandchild))
        .expect("grandchild survivor copy is planned");
    assert_eq!(child_copy.destination_generation(), HeapGeneration::Old);
    assert_eq!(
        grandchild_copy.destination_generation(),
        HeapGeneration::Old
    );

    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("promoted heap-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 2);
    let nursery_writeback = &writeback_plan.writebacks()[1];
    assert_eq!(nursery_writeback.slot(), 1);
    assert_eq!(nursery_writeback.validation_object(), gc_address(child));
    assert_eq!(
        nursery_writeback.writeback_object(),
        child_copy.destination()
    );
    assert_eq!(
        nursery_writeback.source(),
        &HeapEdgeSource::ThunkSelectReceiver
    );
    assert_eq!(
        nursery_writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: grandchild_copy.destination(),
            generation: HeapGeneration::Old,
        }
    );

    let mut stale_slots = [
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(root),
            gc_address(root),
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(child),
            child_copy.destination(),
            0,
            HeapEdgeSource::ThunkSelectReceiver,
            ResolvedValueGeneration::Inline,
        ),
    ];
    let unchanged_stale_slots = stale_slots.clone();
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut stale_slots)
            .expect_err("stale copied nursery field rejects"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(grandchild),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_slots, unchanged_stale_slots);

    let mut slots = [
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(root),
            gc_address(root),
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(child),
            child_copy.destination(),
            0,
            HeapEdgeSource::ThunkSelectReceiver,
            ResolvedValueGeneration::Heap {
                address: gc_address(grandchild),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    let report = writeback_plan
        .apply_to_slots(&mut slots)
        .expect("heap-field writebacks apply");
    assert_eq!(report.writebacks(), 2);
    assert_eq!(
        slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_copy.destination(),
            generation: HeapGeneration::Old,
        }
    );
    assert_eq!(
        slots[1].value(),
        ResolvedValueGeneration::Heap {
            address: grandchild_copy.destination(),
            generation: HeapGeneration::Old,
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
fn collector_poll_minor_gc_heap_field_reference_buffer_rejects_root_slots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
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
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();
    let root_reference_value = AllocationCollectorPollRootReferenceValue::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    );

    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 1);
    assert!(!root_writeback_plan.is_empty());
    let root_writeback = &root_writeback_plan.writebacks()[0];
    assert_eq!(root_writeback.slot(), 0);
    assert_eq!(
        root_writeback.source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(
        root_writeback.expected(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        root_writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            std::slice::from_ref(&root_reference_value),
        )
        .expect("root-only reference buffer derives"),
        vec![ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }]
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(&commit, &[])
            .expect_err("missing root value is rejected"),
        EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
            expected: 1,
            actual: 0,
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            &[
                root_reference_value.clone(),
                AllocationCollectorPollRootReferenceValue::new(
                    EvalRootSource::ValueStack { slot: 1 },
                    ResolvedValueGeneration::Inline,
                ),
            ],
        )
        .expect_err("extra root value is rejected"),
        EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
            expected: 1,
            actual: 2,
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            &[AllocationCollectorPollRootReferenceValue::new(
                EvalRootSource::ValueStack { slot: 1 },
                ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Young,
                },
            )],
        )
        .expect_err("wrong root source is rejected"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 0,
            expected: EvalRootSource::ValueStack { slot: 0 },
            actual: EvalRootSource::ValueStack { slot: 1 },
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            &[AllocationCollectorPollRootReferenceValue::new(
                EvalRootSource::ValueStack { slot: 0 },
                ResolvedValueGeneration::Inline,
            )],
        )
        .expect_err("stale root value is rejected"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );

    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_reference_buffer(&commit)
            .expect_err("root slots still need external storage"),
        EvalHeapError::CollectorPollReferenceSlotNotHeapBacked {
            index: 0,
            root_source: EvalRootSource::ValueStack { slot: 0 },
        }
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("root-only rewrite has no heap-field writebacks");
    assert!(writeback_plan.is_empty());
    assert_eq!(writeback_plan.len(), 0);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_heap_field_reference_buffer_rejects_stale_nursery_field_label() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let grandchild = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("grandchild thunk allocates");
    let child = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(7),
            grandchild,
            IrAttrPathId::new(0),
        ))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
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
    let child_destination = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(child))
        .expect("child survivor copy is planned")
        .destination();
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives before field changes");
    assert_eq!(writeback_plan.len(), 2);
    let nursery_writeback = &writeback_plan.writebacks()[1];
    assert_eq!(nursery_writeback.slot(), 1);
    assert_eq!(nursery_writeback.validation_object(), gc_address(child));
    assert_eq!(nursery_writeback.writeback_object(), child_destination);
    assert_eq!(
        nursery_writeback.source(),
        &HeapEdgeSource::ThunkSelectReceiver
    );

    let child_thunk = heap.clone_thunk(child).expect("child thunk clones");
    let claim = child_thunk
        .cell()
        .begin_force()
        .expect("force claim begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("child thunk should be claimable");
    };
    guard.finish(grandchild).expect("child thunk forced");

    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_reference_buffer(&commit)
            .expect_err("stale nursery field label is rejected"),
        EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
            index: 1,
            expected: HeapEdgeSource::ThunkSelectReceiver,
            actual: Some(HeapEdgeSource::ThunkCachedResult),
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_writeback_plan(&commit)
            .expect_err("stale nursery field label rejects writeback plan"),
        EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
            index: 1,
            expected: HeapEdgeSource::ThunkSelectReceiver,
            actual: Some(HeapEdgeSource::ThunkCachedResult),
        }
    );
}
