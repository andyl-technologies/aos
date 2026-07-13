//! Evaluator-heap unit tests, part 12 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_suspended_thunk_captures() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let with_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("with child thunk allocates");
    let global_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("global child thunk allocates");
    let with_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("with destination thunk allocates");
    let global_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("global destination thunk allocates");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(5),
        with_child,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[global_child]).expect("scoped globals capture");
    let parent = heap
        .alloc_thunk(EvalThunk::with_captures(
            EvalModuleId::ROOT,
            IrId::new(6),
            EvalEnv::default(),
            with_env,
            scoped_globals,
        ))
        .expect("parent thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::with_captures(
            EvalModuleId::ROOT,
            IrId::new(6),
            EvalEnv::default(),
            EvalWithEnv::default(),
            EvalScopedGlobalEnv::default(),
        ))
        .expect("parent destination thunk allocates");

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
            0,
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
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
            1,
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
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
        .expect("copied thunk capture writes apply");

    assert_eq!(report.fields(), 2);
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, parent_destination)
        .expect("destination thunk root records");
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, parent_destination).edges();
    assert_eq!(edges.len(), 2);
    assert!(edges.iter().any(|edge| {
        edge.source()
            == &HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
                index: 0,
            }
            && edge.value().raw_eq(with_destination)
    }));
    assert!(edges.iter().any(|edge| {
        edge.source()
            == &HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
                index: 0,
            }
            && edge.value().raw_eq(global_destination)
    }));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_forced_thunk_cached_result() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let function = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(10),
            IrId::new(11),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("function lambda allocates");
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(12)))
        .expect("argument thunk allocates");
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("forced result thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("forced destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            function,
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("parent destination thunk allocates");
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };
    guard.finish(forced).expect("forced result publishes");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        forced_request,
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
        HeapEdgeSource::ThunkCachedResult,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied forced cached-result write applies");

    assert_eq!(report.fields(), 1);
    let parent_destination_thunk = heap
        .clone_thunk(parent_destination)
        .expect("destination parent thunk clones");
    assert_forced_apply_thunk_cached_result(
        &parent_destination_thunk,
        function,
        argument,
        forced_destination,
    );
    let parent_thunk = heap
        .clone_thunk(parent)
        .expect("source parent thunk clones");
    assert_forced_apply_thunk_cached_result(&parent_thunk, function, argument, forced);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_blackholed_thunk_field() {
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
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            Value::int(1),
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };

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

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("blackholed thunk writes remain unsupported");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
            writeback_object: gc_address(parent),
            field_index: 0,
            field_source: HeapEdgeSource::ThunkApplyArgument,
        }
    );
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Blackhole));
    guard.abort().expect("claim aborts");
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Suspended));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_blackholed_thunk_cached_result() {
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
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            Value::int(1),
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };

    let argument_request = object_copy_request_for_values(
        &heap,
        argument,
        argument_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ThunkCachedResult,
        ResolvedValueGeneration::Heap {
            address: gc_address(argument_destination),
            generation: HeapGeneration::Old,
        },
        argument_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("blackholed cached-result field is not a current live slot");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
            index: 0,
            expected: HeapEdgeSource::ThunkCachedResult,
            actual: Some(HeapEdgeSource::ThunkApplyArgument),
        }
    );
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Blackhole));
    assert!(matches!(parent_thunk.cell().cached_value(), Ok(None)));
    guard.abort().expect("claim aborts");
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Suspended));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_forced_thunk_cached_result() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let function = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(10),
            IrId::new(11),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("function lambda allocates");
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(12)))
        .expect("argument thunk allocates");
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("forced result thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("forced destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            function,
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };
    guard.finish(forced).expect("forced result publishes");

    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![forced_request]);
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
        HeapEdgeSource::ThunkCachedResult,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("forced cached-result rewrite applies");

    assert_eq!(report.fields(), 1);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk still clones");
    assert_forced_apply_thunk_cached_result(&parent_thunk, function, argument, forced_destination);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_parallel_thunk_payload() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("parallel payload thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("parallel payload destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)).with_parallel_payload_cell(tree_walk_error(99), None))
        .expect("parent thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("parent destination thunk allocates");
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    publish_parallel_payload(&parent_thunk, forced);

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        forced_request,
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
        HeapEdgeSource::ThunkParallelPayloadValue,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied parallel payload write applies");

    assert_eq!(report.fields(), 1);
    let parent_destination_thunk = heap
        .clone_thunk(parent_destination)
        .expect("destination parent thunk clones");
    assert_parallel_payload(&parent_destination_thunk, forced_destination);
    let parent_thunk = heap
        .clone_thunk(parent)
        .expect("source parent thunk still clones");
    assert_parallel_payload(&parent_thunk, forced);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_parallel_thunk_payload() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("parallel payload thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("parallel payload destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)).with_parallel_payload_cell(tree_walk_error(99), None))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    publish_parallel_payload(&parent_thunk, forced);

    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![forced_request]);
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
        HeapEdgeSource::ThunkParallelPayloadValue,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct parallel payload write applies");

    assert_eq!(report.fields(), 1);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk still clones");
    assert_parallel_payload(&parent_thunk, forced_destination);
}


#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_reject_malformed_copy_request_set() {
    let mut heap = EvalHeap::new();
    let parent_source = static_gc_address(0x1000_0000);
    let parent_destination = static_gc_address(0x2000_0000);
    let first_child = static_gc_address(0x3000_0000);
    let second_child = static_gc_address(0x4000_0000);
    let shared_child_destination = static_gc_address(0x5000_0000);
    let parent_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        parent_source,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        16,
        8,
    );
    let first_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        first_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let second_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        second_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let writes = [
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            parent_source,
            parent_destination,
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: shared_child_destination,
                generation: HeapGeneration::Old,
            },
            first_child_request,
            parent_request,
        ),
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            parent_source,
            parent_destination,
            1,
            HeapEdgeSource::ListElement { index: 1 },
            ResolvedValueGeneration::Heap {
                address: shared_child_destination,
                generation: HeapGeneration::Old,
            },
            second_child_request,
            parent_request,
        ),
    ];

    let err = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&writes)
        .expect_err("malformed object-copy request set rejects before mutation");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 2,
            source_address: second_child,
            existing_source_address: first_child,
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
fn collector_poll_minor_gc_object_generation_writes_reject_unknown_destination_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    // Since FV-2 no allocation path creates a permanent record, so the
    // destination fixture manufactures one: a worker record flipped to the
    // permanent-shared domain.
    let destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("destination fixture thunk allocates");
    heap.set_allocation_domain_for_test(destination, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let first_source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first source thunk allocates");
    let second_source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("second source thunk allocates");
    let missing_destination = static_gc_address(0x3000_0000);
    let plan = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            gc_address(first_source),
            gc_address(destination),
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            gc_address(second_source),
            missing_destination,
            MinorGcSurvivorAction::PromoteToOld,
            HeapGeneration::Old,
            24,
            8,
        ),
    ])
    .expect("test generation write plan builds");

    assert_eq!(
        heap_generation(&heap, destination),
        HeapGeneration::Permanent
    );
    let err = heap
        .apply_collector_poll_minor_gc_object_generation_writes(&plan)
        .expect_err("unknown destination rejects generation writes");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectGenerationDestination {
            destination: missing_destination
        }
    );
    assert_eq!(
        heap_generation(&heap, destination),
        HeapGeneration::Permanent
    );
}


#[test]
fn collector_poll_minor_gc_object_generation_write_plan_rejects_generation_action_mismatch() {
    let source = static_gc_address(0x1000_0000);
    let destination = static_gc_address(0x2000_0000);
    let err = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            source,
            destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Old,
            24,
            8,
        ),
    ])
    .expect_err("generation/action mismatch is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteGenerationMismatch {
            source_address: source,
            destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        }
    );
}
