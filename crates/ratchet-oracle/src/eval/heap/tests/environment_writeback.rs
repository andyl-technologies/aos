//! Moving-GC writeback coverage for shared lexical frame cells.

use std::sync::Arc;

use super::*;

#[test]
fn copied_heap_field_write_relocates_every_alias_of_a_captured_frame_cell() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = lambda(&mut heap, 1);
    let child_destination = lambda(&mut heap, 2);
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, child).expect("captured slot writes");
    let parent = captured_lambda(&mut heap, 3, Arc::clone(&frame));
    let alias = captured_lambda(&mut heap, 4, Arc::clone(&frame));
    let parent_destination = lambda(&mut heap, 5);
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
    heap.apply_collector_poll_minor_gc_object_generation_writes(
        &copy_plan
            .object_generation_write_plan()
            .expect("generation plan builds"),
    )
    .expect("destination generations write");
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        captured_lambda_slot(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied captured cell write applies");

    assert_eq!(report.fields(), 1);
    assert_captured_slot(&heap, parent_destination, child_destination);
    assert_captured_slot(&heap, alias, child_destination);
    assert!(frame.get(0).expect("shared slot reads").raw_eq(child_destination));
}

#[test]
fn direct_heap_field_write_relocates_an_old_captured_frame_cell() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = lambda(&mut heap, 11);
    let child_destination = lambda(&mut heap, 12);
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, child).expect("captured slot writes");
    let parent = captured_lambda(&mut heap, 13, Arc::clone(&frame));
    let alias = captured_lambda(&mut heap, 14, Arc::clone(&frame));
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        child_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(
        &copy_plan
            .object_generation_write_plan()
            .expect("generation plan builds"),
    )
    .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        captured_lambda_slot(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct captured cell write applies");

    assert_eq!(report.fields(), 1);
    assert_captured_slot(&heap, parent, child_destination);
    assert_captured_slot(&heap, alias, child_destination);
    assert!(frame.get(0).expect("shared slot reads").raw_eq(child_destination));
}

#[test]
fn direct_heap_field_write_relocates_a_suspended_thunk_capture_cell() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = lambda(&mut heap, 21);
    let child_destination = lambda(&mut heap, 22);
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, child).expect("captured slot writes");
    let parent = captured_thunk(&mut heap, 23, Arc::clone(&frame));
    let alias = captured_thunk(&mut heap, 24, Arc::clone(&frame));
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        child_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(
        &copy_plan
            .object_generation_write_plan()
            .expect("generation plan builds"),
    )
    .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct thunk capture write applies");

    assert_eq!(report.fields(), 1);
    assert_captured_thunk_slot(&heap, parent, child_destination);
    assert_captured_thunk_slot(&heap, alias, child_destination);
    assert!(frame.get(0).expect("shared slot reads").raw_eq(child_destination));
}

#[test]
fn direct_heap_field_write_relocates_a_blackholed_thunk_capture_cell() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = lambda(&mut heap, 31);
    let child_destination = lambda(&mut heap, 32);
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, child).expect("captured slot writes");
    let parent = captured_thunk(&mut heap, 33, Arc::clone(&frame));
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let thunk = heap.clone_thunk(parent).expect("thunk handle clones");
    let crate::eval::thunk::ForceClaim::Claimed(guard) =
        thunk.cell().begin_force().expect("thunk claims")
    else {
        panic!("suspended thunk is claimable");
    };

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        child_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(
        &copy_plan
            .object_generation_write_plan()
            .expect("generation plan builds"),
    )
    .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct blackholed capture write applies");

    assert_eq!(report.fields(), 1);
    assert_captured_thunk_slot(&heap, parent, child_destination);
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Blackhole));
    guard.abort().expect("claim aborts");
}

#[test]
fn captured_frame_borrow_conflict_rejects_writeback_before_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = lambda(&mut heap, 31);
    let child_destination = lambda(&mut heap, 32);
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, child).expect("captured slot writes");
    let parent = captured_lambda(&mut heap, 33, Arc::clone(&frame));
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        child_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(
        &copy_plan
            .object_generation_write_plan()
            .expect("generation plan builds"),
    )
    .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        captured_lambda_slot(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );
    let borrowed = frame
        .borrow_slots_for_test()
        .expect("test borrow acquires");

    let error = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("borrowed captured cell rejects writeback");

    assert_eq!(error, EvalHeapError::Environment(EvalEnvError::BorrowConflict));
    assert!(borrowed[0].raw_eq(child));
    drop(borrowed);
    assert!(frame.get(0).expect("shared slot reads").raw_eq(child));
}

fn lambda(heap: &mut EvalHeap, id: u32) -> Value {
    heap.alloc_lambda(EvalLambda::new(
        IrId::new(id),
        IrId::new(id),
        FrameId::new(id),
        EvalEnv::default(),
    ))
    .expect("lambda allocates")
}

fn captured_lambda(heap: &mut EvalHeap, id: u32, frame: Arc<EvalFrame>) -> Value {
    let env = EvalEnv::capture(&[frame]).expect("environment captures");
    heap.alloc_lambda(EvalLambda::new(
        IrId::new(id),
        IrId::new(id),
        FrameId::new(id),
        env,
    ))
    .expect("capturing lambda allocates")
}

fn captured_thunk(heap: &mut EvalHeap, id: u32, frame: Arc<EvalFrame>) -> Value {
    let env = EvalEnv::capture(&[frame]).expect("environment captures");
    heap.alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(id), env))
        .expect("capturing thunk allocates")
}

const fn captured_lambda_slot() -> HeapEdgeSource {
    HeapEdgeSource::CapturedEnv {
        owner: CapturedRootOwner::Lambda,
        frame: 0,
        slot: 0,
    }
}

fn assert_captured_slot(heap: &EvalHeap, owner: Value, expected: Value) {
    let lambda = heap.get_lambda(owner).expect("capturing lambda remains typed");
    assert!(
        lambda.env().frames()[0]
            .get(0)
            .expect("captured slot reads")
            .raw_eq(expected)
    );
}

fn assert_captured_thunk_slot(heap: &EvalHeap, owner: Value, expected: Value) {
    let thunk = heap.clone_thunk(owner).expect("capturing thunk remains typed");
    let EvalThunkKind::Node { env, .. } = thunk.kind() else {
        panic!("capturing thunk remains suspended");
    };
    assert!(
        env.frames()[0]
            .get(0)
            .expect("captured slot reads")
            .raw_eq(expected)
    );
}
