//! Evaluator-heap unit tests, part 10 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_lambda_capture_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
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
    let with_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("with child lambda allocates");
    let global_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("global child lambda allocates");
    let with_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("with destination lambda allocates");
    let global_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("global destination lambda allocates");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(8),
        with_child,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[global_child]).expect("scoped globals capture");
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
            scoped_globals,
        ))
        .expect("parent lambda allocates");
    let parent_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("parent destination lambda allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let with_request = object_copy_request_for_values(
        &heap,
        with_child,
        with_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let global_request = object_copy_request_for_values(
        &heap,
        global_child,
        global_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        with_request,
        global_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let writes = [
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            gc_address(parent_destination),
            1,
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(with_destination),
                generation: HeapGeneration::Old,
            },
            with_request,
            parent_request,
        ),
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            gc_address(parent_destination),
            2,
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(global_destination),
                generation: HeapGeneration::Old,
            },
            global_request,
            parent_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&writes)
        .expect("copied lambda capture field writes apply");

    assert_eq!(report.fields(), 2);
    let lambda = heap
        .get_lambda(parent_destination)
        .expect("destination lambda remains typed");
    assert_eq!(lambda.pattern(), IrId::new(5));
    assert_eq!(lambda.body(), IrId::new(6));
    assert_eq!(lambda.frame(), FrameId::new(7));
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
            .raw_eq(with_destination)
    );
    assert_eq!(lambda.scoped_global_env().scopes().len(), 1);
    assert!(lambda.scoped_global_env().scopes()[0].raw_eq(global_destination));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_worker_domain_flat_lists() {
    // Lists are flat and permanent since FV-1: a direct write that claims a
    // list is worker-domain (the pre-FV-1 "old worker list" shape) must fail
    // the generation gate loudly without mutating the flat payload.
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
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("worker-domain flat-list write is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object: gc_address(parent),
            expected: HeapGeneration::Old,
            actual: HeapGeneration::Permanent,
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
fn collector_poll_minor_gc_direct_heap_field_writes_merge_same_flat_attrs_fields() {
    // Two direct writes against the SAME flat attrset must merge through one
    // staged entry storage (doc 30 FV-2 coupling (c)): the second write sees
    // the first write's staged entry, and one commit publishes both.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let first_key = symbols.intern(b"alpha").expect("alpha interns");
    let second_key = symbols.intern(b"beta").expect("beta interns");
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
    let parent_attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(first_key, first_child),
            AttrEntry::new(second_key, second_child),
        ],
        &symbols,
    )
    .expect("attrs build");
    let parent = heap
        .alloc_attrs(0, parent_attrs)
        .expect("parent attrs allocate");

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
            HeapEdgeSource::AttrBinding {
                shape: 0,
                slot: 0,
                key: first_key,
            },
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
            HeapEdgeSource::AttrBinding {
                shape: 0,
                slot: 1,
                key: second_key,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(second_destination),
                generation: HeapGeneration::Old,
            },
            second_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&writes)
        .expect("merged flat attrs field writes apply");

    assert_eq!(report.fields(), 2);
    let attrs = heap.get_attrs(parent).expect("parent attrs remain typed");
    assert!(
        attrs
            .get(first_key)
            .expect("first rewritten binding exists")
            .raw_eq(first_destination)
    );
    assert!(
        attrs
            .get(second_key)
            .expect("second rewritten binding exists")
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
fn collector_poll_minor_gc_direct_heap_field_writes_reject_worker_domain_flat_attrs() {
    // Attrsets are flat and permanent since FV-2: a direct write that claims
    // an attrset is worker-domain (the pre-FV-2 "old worker attrs" shape)
    // must fail the generation gate loudly without mutating the flat payload.
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
    let parent = heap
        .alloc_attrs(0, parent_attrs)
        .expect("parent attrs allocate");

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
        HeapAllocationDomain::Worker,
        gc_address(parent),
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
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("worker-domain flat-attrs write is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object: gc_address(parent),
            expected: HeapGeneration::Old,
            actual: HeapGeneration::Permanent,
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
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_old_primop_args() {
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
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

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
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct old primop argument write applies");

    assert_eq!(report.fields(), 1);
    let primop = heap
        .get_primop(parent)
        .expect("parent primop remains typed");
    assert_eq!(primop.builtin(), Some(builtin));
    assert_eq!(primop.symbol(), symbol);
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].id(), IrId::new(7));
    assert_eq!(primop.args()[0].span(), Span::new(9, 12));
    assert!(primop.args()[0].value().raw_eq(child_destination));
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Old);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_old_lambda_capture_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
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
    let with_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("with child lambda allocates");
    let global_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("global child lambda allocates");
    let with_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("with destination lambda allocates");
    let global_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("global destination lambda allocates");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(8),
        with_child,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[global_child]).expect("scoped globals capture");
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
            scoped_globals,
        ))
        .expect("parent lambda allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let with_request = object_copy_request_for_values(
        &heap,
        with_child,
        with_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let global_request = object_copy_request_for_values(
        &heap,
        global_child,
        global_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        with_request,
        global_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generations write");
    let writes = [
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            1,
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(with_destination),
                generation: HeapGeneration::Old,
            },
            with_request,
        ),
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            2,
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(global_destination),
                generation: HeapGeneration::Old,
            },
            global_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&writes)
        .expect("direct old lambda capture field writes apply");

    assert_eq!(report.fields(), 2);
    let lambda = heap
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert_eq!(lambda.pattern(), IrId::new(5));
    assert_eq!(lambda.body(), IrId::new(6));
    assert_eq!(lambda.frame(), FrameId::new(7));
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
            .raw_eq(with_destination)
    );
    assert_eq!(lambda.scoped_global_env().scopes().len(), 1);
    assert!(lambda.scoped_global_env().scopes()[0].raw_eq(global_destination));
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Old);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_stale_field_value_without_mutation() {
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
    let stale_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("stale child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![stale_child]))
        .expect("parent list allocates");

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

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("stale old field is rejected");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
            writeback_object,
            field_index: 0,
            field_source,
            expected,
            actual,
        } if writeback_object == gc_address(parent)
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && expected == (ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            })
            && actual == (ResolvedValueGeneration::Heap {
                address: gc_address(stale_child),
                generation: HeapGeneration::Young,
            })
    ));
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("original element exists")
            .raw_eq(stale_child)
    );
}
