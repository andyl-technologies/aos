//! Evaluator-heap unit tests, part 11 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_permanent_list_fields() {
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
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::PermanentShared);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("permanent list field write applies");

    assert_eq!(report.fields(), 1);
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("rewritten element exists")
            .raw_eq(child_destination)
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
fn collector_poll_minor_gc_heap_field_writes_merge_mixed_same_record_fields() {
    // Lists are flat since FV-1, so a partially applied builtin carries the
    // mixed copied+direct writes against one record.
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
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
    let copied_source_parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![
                EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), first_child),
                EvalPrimOpArg::new(IrId::new(8), Span::new(13, 16), second_child),
            ],
        ))
        .expect("copied source parent primop allocates");
    let parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![
                EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), first_child),
                EvalPrimOpArg::new(IrId::new(8), Span::new(13, 16), second_child),
            ],
        ))
        .expect("parent primop allocates");
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let parent_request = object_copy_request_for_values(
        &heap,
        copied_source_parent,
        parent,
        MinorGcSurvivorAction::PromoteToOld,
    );
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
        parent_request,
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
    let copied_write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(copied_source_parent),
        gc_address(parent),
        1,
        HeapEdgeSource::PrimopArgument { index: 1 },
        ResolvedValueGeneration::Heap {
            address: gc_address(second_destination),
            generation: HeapGeneration::Old,
        },
        second_request,
        parent_request,
    );
    let direct_write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(first_destination),
            generation: HeapGeneration::Old,
        },
        first_request,
    );

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes(&[copied_write], &[direct_write])
        .expect("mixed same-record heap field writes apply");

    assert_eq!(copied_report.fields(), 1);
    assert_eq!(direct_report.fields(), 1);
    let primop = heap
        .get_primop(parent)
        .expect("parent primop remains typed");
    assert!(primop.args()[0].value().raw_eq(first_destination));
    assert!(primop.args()[1].value().raw_eq(second_destination));
}


#[test]
fn collector_poll_minor_gc_heap_field_writes_reject_cross_branch_malformed_request_set() {
    let mut heap = EvalHeap::new();
    let parent_source = static_gc_address(0x1000_0000);
    let parent_destination = static_gc_address(0x2000_0000);
    let copied_child = static_gc_address(0x3000_0000);
    let direct_child = static_gc_address(0x4000_0000);
    let shared_child_destination = static_gc_address(0x5000_0000);
    let parent_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        parent_source,
        parent_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        16,
        8,
    );
    let copied_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        copied_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let direct_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        direct_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let copied_write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        parent_source,
        parent_destination,
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: shared_child_destination,
            generation: HeapGeneration::Old,
        },
        copied_child_request,
        parent_request,
    );
    let direct_write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        parent_destination,
        1,
        HeapEdgeSource::ListElement { index: 1 },
        ResolvedValueGeneration::Heap {
            address: shared_child_destination,
            generation: HeapGeneration::Old,
        },
        direct_child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_heap_field_writes(&[copied_write], &[direct_write])
        .expect_err("cross-branch duplicate destination rejects before heap mutation");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 2,
            source_address: direct_child,
            existing_source_address: copied_child,
            destination: shared_child_destination,
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
fn collector_poll_minor_gc_direct_heap_field_writes_reject_young_replacements_without_mutation() {
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

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("direct old-to-young field write is rejected");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteYoungReplacementUnsupported {
            writeback_object,
            field_index: 0,
            field_source,
            replacement,
            generation: HeapGeneration::Young,
        } if writeback_object == gc_address(parent)
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && replacement == gc_address(child_destination)
    ));
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
fn collector_poll_minor_gc_heap_field_writes_publish_barrier_for_direct_young_replacement() {
    // Lists are flat since FV-1, so an old worker primop carries the direct
    // old-to-young write whose barrier must publish.
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
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[write],
            &mut remembered_set,
            &mut card_table,
        )
        .expect("barrier-aware direct old-to-young write applies");

    assert_eq!(copied_report.fields(), 0);
    assert_eq!(direct_report.fields(), 1);
    let primop = heap
        .get_primop(parent)
        .expect("parent primop remains typed");
    assert!(primop.args()[0].value().raw_eq(child_destination));
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(parent),
            gc_address(child_destination)
        )]
    );
    assert!(card_table.snapshot().covers_source(gc_address(parent)));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_heap_field_writes_publish_barrier_for_permanent_young_replacement() {
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
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::PermanentShared);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[write],
            &mut remembered_set,
            &mut card_table,
        )
        .expect("barrier-aware permanent-to-young write applies");

    assert_eq!(copied_report.fields(), 0);
    assert_eq!(direct_report.fields(), 1);
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("rewritten element exists")
            .raw_eq(child_destination)
    );
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(parent),
            gc_address(child_destination)
        )]
    );
    assert!(card_table.snapshot().covers_source(gc_address(parent)));
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Permanent);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_heap_field_writes_publish_lambda_capture_barrier() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let lexical_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lexical child lambda allocates");
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
    let with_env =
        EvalWithEnv::capture(&[EvalWithScope::new(EvalModuleId::ROOT, IrId::new(8), child)])
            .expect("with env captures");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, lexical_child).expect("lexical slot writes");
    let env = EvalEnv::capture(&[frame]).expect("lexical env captures");
    let parent = heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(5),
            IrId::new(6),
            FrameId::new(7),
            env,
            with_env,
            EvalScopedGlobalEnv::default(),
        ))
        .expect("parent lambda allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        1,
        HeapEdgeSource::CapturedWithScope {
            owner: CapturedRootOwner::Lambda,
            index: 0,
        },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[write],
            &mut remembered_set,
            &mut card_table,
        )
        .expect("barrier-aware direct old-to-young lambda capture write applies");

    assert_eq!(copied_report.fields(), 0);
    assert_eq!(direct_report.fields(), 1);
    let lambda = heap
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert_eq!(lambda.env().frames().len(), 1);
    assert!(
        lambda.env().frames()[0]
            .get(0)
            .expect("lexical slot reads")
            .raw_eq(lexical_child)
    );
    assert_eq!(lambda.with_scope_env().scopes().len(), 1);
    assert_eq!(lambda.with_scope_env().scopes()[0].scope(), IrId::new(8));
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(child_destination)
    );
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(parent),
            gc_address(child_destination)
        )]
    );
    assert!(card_table.snapshot().covers_source(gc_address(parent)));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_suspended_thunk_apply_argument() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let function = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("function lambda allocates");
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("argument thunk allocates");
    let argument_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("argument destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(5),
            Span::new(0, 1),
            function,
            EvalModuleId::ROOT,
            IrId::new(6),
            argument,
        ))
        .expect("parent apply thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let argument_request = object_copy_request_for_values(
        &heap,
        argument,
        argument_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![argument_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        1,
        HeapEdgeSource::ThunkApplyArgument,
        ResolvedValueGeneration::Heap {
            address: gc_address(argument_destination),
            generation: HeapGeneration::Old,
        },
        argument_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct thunk apply argument write applies");

    assert_eq!(report.fields(), 1);
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, parent)
        .expect("apply thunk root records");
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, parent).edges();
    assert_eq!(edges.len(), 2);
    assert!(edges.iter().any(|edge| {
        edge.source() == &HeapEdgeSource::ThunkApplyFunction && edge.value().raw_eq(function)
    }));
    assert!(edges.iter().any(|edge| {
        edge.source() == &HeapEdgeSource::ThunkApplyArgument
            && edge.value().raw_eq(argument_destination)
    }));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_preserve_parallel_payload_on_suspended_thunk_write()
 {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("argument thunk allocates");
    let argument_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("argument destination thunk allocates");
    let payload = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("parallel payload thunk allocates");
    let parent = heap
        .alloc_thunk(
            EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(4),
                Span::new(0, 1),
                Value::int(1),
                EvalModuleId::ROOT,
                IrId::new(5),
                argument,
            )
            .with_parallel_payload_cell(tree_walk_error(99), None),
        )
        .expect("parent apply thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    publish_parallel_payload(&parent_thunk, payload);

    let argument_request = object_copy_request_for_values(
        &heap,
        argument,
        argument_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![argument_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ThunkApplyArgument,
        ResolvedValueGeneration::Heap {
            address: gc_address(argument_destination),
            generation: HeapGeneration::Old,
        },
        argument_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct thunk apply argument write applies");

    assert_eq!(report.fields(), 1);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk still clones");
    let EvalThunkKind::Apply { argument_value, .. } = parent_thunk.kind() else {
        panic!("parent remains an apply thunk");
    };
    assert!(argument_value.raw_eq(argument_destination));
    assert_parallel_payload(&parent_thunk, payload);
}
