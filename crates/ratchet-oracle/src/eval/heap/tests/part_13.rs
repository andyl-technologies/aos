//! Evaluator-heap unit tests, part 13 of 16 (RFC-0007 §2 split, #9).
//!
//! Move-only item-boundary split of the `tests.rs` inline body; each
//! test keeps its `#[cfg]`/doc prefix. No test changed.

#![allow(unused_imports)]

use super::super::*;
use super::*;

#[test]
fn collector_poll_minor_gc_object_generation_write_plan_rejects_destination_source_overlap() {
    let first_source = static_gc_address(0x1000_0000);
    let second_source = static_gc_address(0x2000_0000);
    let first_destination = static_gc_address(0x3000_0000);
    let second_destination = static_gc_address(0x4000_0000);

    let err = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            first_source,
            first_destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            second_source,
            first_source,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
    ])
    .expect_err("destination matching an earlier source is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
            index: 1,
            source_address: second_source,
            existing_source_address: first_source,
            destination: first_source,
        }
    );

    let err = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            first_source,
            second_source,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            second_source,
            second_destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
    ])
    .expect_err("earlier destination matching a later source is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
            index: 1,
            source_address: first_source,
            existing_source_address: second_source,
            destination: second_source,
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
fn collector_poll_minor_gc_plan_rejects_unremembered_permanent_to_worker_edge() {
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
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("missing remembered edge is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollRememberedEdge {
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
fn collector_poll_minor_gc_plan_uses_remembered_permanent_edge() {
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

    assert_eq!(
        planned.roots(),
        &[ResolvedValueGeneration::Heap {
            address: gc_address(root),
            generation: HeapGeneration::Permanent,
        }]
    );
    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(planned.reference_slots().len(), 2);
    assert_eq!(
        planned.reference_slots()[0].source(),
        &AllocationCollectorPollReferenceSource::Root {
            source: EvalRootSource::ValueStack { slot: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(root),
            generation: HeapGeneration::Permanent,
        }
    );
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: RememberedEdge::new(gc_address(root), gc_address(child)),
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );

    let nursery_layouts = [NurseryObjectLayout::new(gc_address(child), 16, 8)];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan builds");
    assert_eq!(destinations.allocation_plan().nursery_bytes(), 16);
    assert_eq!(destinations.allocation_plan().old_bytes(), 0);
    assert_eq!(destinations.placement_plan().nursery_reserved_bytes(), 16);
    assert_eq!(destinations.placement_plan().old_reserved_bytes(), 0);
    assert_eq!(destinations.destinations().len(), 1);
    let child_destination = destinations.destinations()[0].destination();
    assert_eq!(child_destination, static_gc_address(0x1000_2000));
    let relocation_destinations = destinations.destinations();
    let relocation_plan =
        MinorGcRelocationPlan::from_minor_gc_plan(planned.plan(), relocation_destinations)
            .expect("relocation plan builds");
    let rewrite_plan = planned
        .reference_rewrite_plan(&relocation_plan)
        .expect("reference rewrite plan builds");
    assert_eq!(rewrite_plan.rewrites().len(), 1);
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 1);
    assert_eq!(rewrite_plan.rewrites()[0].source(), gc_address(child));
    assert_eq!(rewrite_plan.rewrites()[0].destination(), child_destination);

    assert_eq!(planned.remembered_set(), &remembered_set);
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    assert_eq!(commit.reference_slots(), planned.reference_slots());
    assert_eq!(
        commit.commit_plan().remembered_set_refresh().refreshes()[0].retained_edge(),
        Some(RememberedEdge::new(gc_address(root), child_destination))
    );
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[RememberedEdge::new(gc_address(root), child_destination)]
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    assert!(!writeback_plan.is_empty());
    let writeback = &writeback_plan.writebacks()[0];
    assert_eq!(writeback.slot(), 1);
    assert_eq!(writeback.validation_object(), gc_address(root));
    assert_eq!(writeback.writeback_object(), gc_address(root));
    assert_eq!(writeback.field_index(), 0);
    assert_eq!(
        writeback.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        writeback.expected(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let mismatch_commit = planned
        .commit_plan(&destinations)
        .expect("reference-mismatch commit plan builds");
    let mismatch_child_source_bytes = [5u8; 16];
    let mut mismatch_child_destination_bytes = [0u8; 16];
    let mut mismatch_object_byte_copies = [MinorGcObjectByteCopyBuffer::new(
        gc_address(child),
        child_destination,
        &mismatch_child_source_bytes,
        &mut mismatch_child_destination_bytes,
    )];
    let mut mismatch_forwarding_slots = mismatch_commit
        .forwarding_slot_buffer()
        .expect("mismatch forwarding slot buffer derives");
    let mut mismatch_references = planned.reference_values().collect::<Vec<_>>();
    let expected_root_reference = mismatch_references[0];
    mismatch_references[0] = ResolvedValueGeneration::Inline;
    let mut mismatch_remembered_set = remembered_set.clone();
    assert_eq!(
        mismatch_commit
            .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
                &mut mismatch_object_byte_copies,
                &mut mismatch_forwarding_slots,
                &mut mismatch_references,
                &mut mismatch_remembered_set,
            ))
            .expect_err("same-length reference mismatch is rejected"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: expected_root_reference,
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(mismatch_child_destination_bytes, [0u8; 16]);
    assert!(mismatch_forwarding_slots[0].is_empty());
    assert_eq!(
        mismatch_references,
        vec![
            ResolvedValueGeneration::Inline,
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(mismatch_remembered_set, remembered_set);

    let expected_next_remembered_set = commit.commit_plan().next_remembered_set().clone();
    let child_source_bytes = [4u8; 16];
    let mut child_destination_bytes = [0u8; 16];
    let mut object_byte_copies = [MinorGcObjectByteCopyBuffer::new(
        gc_address(child),
        child_destination,
        &child_source_bytes,
        &mut child_destination_bytes,
    )];
    let mut forwarding_slots = commit
        .forwarding_slot_buffer()
        .expect("remembered-edge forwarding slot buffer derives");
    let mut references = planned.reference_values().collect::<Vec<_>>();
    let mut commit_remembered_set = remembered_set.clone();

    commit
        .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
            &mut object_byte_copies,
            &mut forwarding_slots,
            &mut references,
            &mut commit_remembered_set,
        ))
        .expect("remembered-edge commit buffers apply");

    assert_eq!(child_destination_bytes, child_source_bytes);
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        references,
        vec![
            ResolvedValueGeneration::Heap {
                address: gc_address(root),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: child_destination,
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(commit_remembered_set, expected_next_remembered_set);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_card_table_plan_requires_dirty_remembered_source_card() {
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
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let edge = RememberedEdge::new(gc_address(root), gc_address(child));
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(edge)
        .expect("remembered edge records");
    let card_table = GcCardTable::default();

    let error = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("missing dirty source card is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollDirtyCard {
            source_address: edge.source(),
            target_address: edge.target(),
            card_index: card_table.snapshot().card_index_for_source(edge.source()),
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
fn collector_poll_minor_gc_card_table_plan_accepts_dirty_remembered_source_card() {
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
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let edge = RememberedEdge::new(gc_address(root), gc_address(child));
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(edge)
        .expect("remembered edge records");
    let mut card_table = GcCardTable::default();
    card_table
        .mark_source(edge.source())
        .expect("remembered source card marks");

    let planned = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("dirty card admits remembered edge");

    assert_eq!(planned.remembered_set(), &remembered_set);
    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), edge.target());
    assert_eq!(planned.reference_slots().len(), 2);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_card_table_plan_adds_dirty_unremembered_survivor_edge() {
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
        .expect("dirty unremembered edge enters the survivor frontier");

    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(planned.reference_slots().len(), 2);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::DirtyOldField {
            object: gc_address(permanent_parent),
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
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
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan includes dirty old-field survivor");
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();

    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites().len(),
        1
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites()[0].slot(),
        1
    );
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[RememberedEdge::new(
            gc_address(permanent_parent),
            child_destination,
        )]
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("dirty old-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    assert_eq!(writeback_plan.writebacks()[0].slot(), 1);
    assert_eq!(
        writeback_plan.writebacks()[0].validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        writeback_plan.writebacks()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(writeback_plan.writebacks()[0].field_index(), 0);
    assert_eq!(
        writeback_plan.writebacks()[0].replacement(),
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
fn collector_poll_minor_gc_card_table_plan_promotes_dirty_unremembered_survivor_edge() {
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
            MinorGcPromotionPolicy::new(0),
        )
        .expect("dirty unremembered edge enters the survivor frontier");

    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(
        planned.plan().survivors()[0].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(planned.reference_slots().len(), 2);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::DirtyOldField {
            object: gc_address(permanent_parent),
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );

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
        .expect("commit plan includes promoted dirty old-field survivor");
    let copy = &commit.commit_plan().object_copies().copies()[0];

    assert_eq!(copy.source(), gc_address(child));
    assert_eq!(copy.destination_generation(), HeapGeneration::Old);
    assert_eq!(commit.commit_plan().next_remembered_set().edges(), &[]);
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites().len(),
        1
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites()[0].slot(),
        1
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites()[0].replacement(),
        copy.relocated_value()
    );

    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("promoted dirty old-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    assert_eq!(writeback_plan.writebacks()[0].slot(), 1);
    assert_eq!(
        writeback_plan.writebacks()[0].validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        writeback_plan.writebacks()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        writeback_plan.writebacks()[0].replacement(),
        ResolvedValueGeneration::Heap {
            address: copy.destination(),
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
fn collector_poll_minor_gc_card_table_plan_preserves_remembered_order_before_dirty_edges() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let remembered_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("remembered child thunk allocates");
    let dirty_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("dirty child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![remembered_child, dirty_child]))
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
    let remembered_edge =
        RememberedEdge::new(gc_address(permanent_parent), gc_address(remembered_child));
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(remembered_edge)
        .expect("remembered edge records");
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
        .expect("dirty edge appends after remembered frontier");

    assert_eq!(planned.plan().survivors().len(), 2);
    assert_eq!(
        planned.plan().survivors()[0].address(),
        gc_address(remembered_child)
    );
    assert_eq!(
        planned.plan().survivors()[1].address(),
        gc_address(dirty_child)
    );
    assert_eq!(planned.reference_slots().len(), 3);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: remembered_edge,
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(remembered_child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        planned.reference_slots()[2].source(),
        &AllocationCollectorPollReferenceSource::DirtyOldField {
            object: gc_address(permanent_parent),
            field_index: 1,
            source: HeapEdgeSource::ListElement { index: 1 },
        }
    );
    assert_eq!(
        planned.reference_slots()[2].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(dirty_child),
            generation: HeapGeneration::Young,
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
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan preserves frontier order");
    let remembered_destination = commit.commit_plan().object_copies().copies()[0].destination();
    let dirty_destination = commit.commit_plan().object_copies().copies()[1].destination();
    let rewrites = commit.commit_plan().reference_rewrites().rewrites();

    assert_eq!(rewrites.len(), 2);
    assert_eq!(rewrites[0].slot(), 1);
    assert_eq!(rewrites[1].slot(), 2);
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[
            RememberedEdge::new(gc_address(permanent_parent), remembered_destination),
            RememberedEdge::new(gc_address(permanent_parent), dirty_destination),
        ]
    );
}
