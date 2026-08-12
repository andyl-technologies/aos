//! Evaluator-heap unit tests, part 9 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_object_body_writes_bind_existing_destination_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(7),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, source),
        record_layout_align(&heap, source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![request]);

    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let report = heap
        .apply_collector_poll_minor_gc_object_body_writes(&plan)
        .expect("object body writes apply");

    assert_eq!(report.objects(), 1);
    assert_eq!(report.copied_to_nursery(), 1);
    assert_eq!(report.promoted_to_old(), 0);
    assert_eq!(report.payload_bytes(), record_layout_size(&heap, source));
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda)
        .expect("destination record body is bound to the source body");
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert_eq!(heap_generation(&heap, source), HeapGeneration::Young);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_object_body_and_generation_writes_bind_body_and_promote_destination() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(7),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(source),
        gc_address(destination),
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        record_layout_size(&heap, source),
        record_layout_align(&heap, source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![request]);
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let report = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&plan)
        .expect("paired body/generation writes apply");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda)
        .expect("destination body is bound to source body");
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Old);
    assert_eq!(heap_generation(&heap, source), HeapGeneration::Young);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_object_body_and_generation_writes_validate_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(7),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(source),
        gc_address(destination),
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        record_layout_size(&heap, source),
        record_layout_align(&heap, source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![request]);

    let report = heap
        .validate_collector_poll_minor_gc_object_body_and_generation_writes(&plan)
        .expect("paired body/generation writes validate");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_object_body_and_generation_writes_reject_duplicate_destination_without_mutation()
 {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("first source lambda allocates");
    let second_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("second source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let first_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(first_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, first_source),
        record_layout_align(&heap, first_source),
    );
    let second_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(second_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, second_source),
        record_layout_align(&heap, second_source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        first_request,
        second_request,
    ]);
    let generation_before = heap_generation(&heap, destination);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(first_request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let err = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&plan)
        .expect_err("duplicate destination is rejected before mutation");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 1,
            source_address,
            existing_source_address,
            destination: actual_destination,
        } if source_address == gc_address(second_source)
            && existing_source_address == gc_address(first_source)
            && actual_destination == gc_address(destination)
    ));
    assert_eq!(heap_generation(&heap, destination), generation_before);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(first_request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_object_body_writes_reject_malformed_plan_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("first source lambda allocates");
    let second_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("second source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let first_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(first_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, first_source),
        record_layout_align(&heap, first_source),
    );
    let second_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(second_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, second_source),
        record_layout_align(&heap, second_source),
    );
    let duplicate_destination_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
            first_request,
            second_request,
        ]);

    let err = heap
        .apply_collector_poll_minor_gc_object_body_writes(&duplicate_destination_plan)
        .expect_err("duplicate destination rejects body writes");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 1,
            source_address: gc_address(second_source),
            existing_source_address: gc_address(first_source),
            destination: gc_address(destination),
        }
    );
    assert_eq!(
        heap.get_lambda(destination)
            .expect("destination remains a lambda")
            .pattern(),
        IrId::new(0)
    );

    let destination_is_source_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(first_source),
        gc_address(first_source),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, first_source),
        record_layout_align(&heap, first_source),
    );
    let destination_is_source_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
            destination_is_source_request,
        ]);

    let err = heap
        .apply_collector_poll_minor_gc_object_body_writes(&destination_is_source_plan)
        .expect_err("destination matching source rejects body writes");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDestinationIsSource {
            source_address: gc_address(first_source),
        }
    );
    assert_eq!(
        heap.get_lambda(first_source)
            .expect("source remains a lambda")
            .pattern(),
        IrId::new(1)
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_reject_flat_list_writeback_objects() {
    // Lists are flat and permanent since FV-1, so they are never minor-GC
    // survivors: a copied heap-field write naming a flat list as its
    // relocated writeback object must fail loudly without mutation.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("parent list allocates");
    let parent_destination = heap
        .alloc_list(NixList::new(vec![Value::int(0)]))
        .expect("parent destination list allocates");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
        parent_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect_err("flat-list copied writeback object is rejected");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollSurvivorAddress {
            address: gc_address(parent),
        }
    );
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(list.get(0).expect("original element exists").raw_eq(child));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_bound_thunk_select_receiver() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let receiver = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("receiver thunk allocates");
    let receiver_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("receiver destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(3),
            receiver,
            IrAttrPathId::new(0),
        ))
        .expect("parent select thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(3),
            Value::int(0),
            IrAttrPathId::new(0),
        ))
        .expect("parent destination thunk allocates");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let receiver_request = object_copy_request_for_values(
        &heap,
        receiver,
        receiver_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        receiver_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::ThunkSelectReceiver,
        ResolvedValueGeneration::Heap {
            address: gc_address(receiver_destination),
            generation: HeapGeneration::Old,
        },
        receiver_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied thunk select receiver write applies");

    assert_eq!(report.fields(), 1);
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, parent_destination)
        .expect("destination thunk root records");
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, parent_destination).edges();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].source(), &HeapEdgeSource::ThunkSelectReceiver);
    assert!(edges[0].value().raw_eq(receiver_destination));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_merge_same_flat_list_fields() {
    // Two direct writes against the SAME flat list must merge through one
    // staged spine (doc 30 FV-1 coupling (c)): the second write sees the
    // first write's staged element, and one commit publishes both.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("first child lambda allocates");
    let second_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("second child lambda allocates");
    let first_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("first destination lambda allocates");
    let second_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("second destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![first_child, second_child]))
        .expect("parent list allocates");

    let first_request = object_copy_request_for_values(
        &heap,
        first_child,
        first_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let second_request = object_copy_request_for_values(
        &heap,
        second_child,
        second_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        first_request,
        second_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let writes = [
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first_destination),
                generation: HeapGeneration::Old,
            },
            first_request,
        ),
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            1,
            HeapEdgeSource::ListElement { index: 1 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second_destination),
                generation: HeapGeneration::Old,
            },
            second_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&writes)
        .expect("merged flat list field writes apply");

    assert_eq!(report.fields(), 2);
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("first rewritten element exists")
            .raw_eq(first_destination)
    );
    assert!(
        list.get(1)
            .expect("second rewritten element exists")
            .raw_eq(second_destination)
    );
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Permanent);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_reject_flat_attrs_writeback_objects() {
    // Attrsets are flat and permanent since FV-2, so they are never minor-GC
    // survivors: a copied heap-field write naming a flat attrset as its
    // relocated writeback object must fail loudly without mutation.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent_attrs =
        FlatAttrs::new(vec![AttrEntry::new(key, child)], &symbols).expect("attrs build");
    let parent_destination_attrs =
        FlatAttrs::new(vec![AttrEntry::new(key, Value::int(0))], &symbols)
            .expect("destination attrs build");
    let parent = heap
        .alloc_attrs(0, parent_attrs)
        .expect("parent attrs allocate");
    let parent_destination = heap
        .alloc_attrs(0, parent_destination_attrs)
        .expect("parent destination attrs allocate");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::AttrBinding {
            shape: 0,
            slot: 0,
            key,
        },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
        parent_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect_err("flat-attrs copied writeback object is rejected");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollSurvivorAddress {
            address: gc_address(parent),
        }
    );
    let attrs = heap.get_attrs(parent).expect("parent attrs remain typed");
    assert!(
        attrs
            .get(key)
            .expect("original binding exists")
            .raw_eq(child)
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_bound_primop_args() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), child)],
        ))
        .expect("parent primop allocates");
    let parent_destination = heap
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("parent destination primop allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        child_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied primop argument write applies");

    assert_eq!(report.fields(), 1);
    let primop = heap
        .get_primop(parent_destination)
        .expect("destination primop remains typed");
    assert_eq!(primop.builtin(), Some(builtin));
    assert_eq!(primop.symbol(), symbol);
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].id(), IrId::new(7));
    assert_eq!(primop.args()[0].span(), Span::new(9, 12));
    assert!(primop.args()[0].value().raw_eq(child_destination));
}
