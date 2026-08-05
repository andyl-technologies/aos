//! Evaluator-heap unit tests, part 8 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_reserved_destination_records_bind_existing_heap_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let child_address = gc_address(child);
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");

    assert_eq!(reservations.len(), 1);
    assert!(!reservations.is_empty());
    let reservation = reservations.reservations()[0];
    assert_eq!(reservation.source(), child_address);
    assert_eq!(reservation.tag(), ValueTag::Thunk);
    assert_eq!(
        gc_address(reservation.destination_value()),
        reservation.destination()
    );
    assert_eq!(
        heap_generation(&heap, reservation.destination_value()),
        HeapGeneration::Young
    );
    assert_eq!(
        allocation_domain(&heap, reservation.destination_value()),
        HeapAllocationDomain::Worker
    );

    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("destination reservation requests a collector poll");
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
        .plan_collector_poll_minor_gc_reserved_relocation_destinations(&planned, &reservations)
        .expect("reserved destinations plan");

    assert_eq!(destinations.destinations().len(), 1);
    assert_eq!(destinations.destinations()[0].source(), child_address);
    assert_eq!(
        destinations.destinations()[0].destination(),
        reservation.destination()
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan accepts reserved destination");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    assert_eq!(byte_copy_plan.len(), 1);
    let request = byte_copy_plan.requests()[0];
    assert_eq!(request.source(), child_address);
    assert_eq!(request.destination(), reservation.destination());
    assert_eq!(request.action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(request.destination_generation(), HeapGeneration::Young);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Thunk),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let report = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&byte_copy_plan)
        .expect("paired body/generation writes apply");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.body_write_report().copied_to_nursery(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(
        heap_generation(&heap, reservation.destination_value()),
        HeapGeneration::Young
    );
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Thunk)
        .expect("destination body is bound to source body");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_reserved_destination_records_support_promotions() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let child_address = gc_address(child);
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");
    let reservation = reservations.reservations()[0];
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("destination reservation requests a collector poll");
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
            MinorGcPromotionPolicy::new(0),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_reserved_relocation_destinations(&planned, &reservations)
        .expect("reserved destinations plan");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan accepts reserved destination");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");

    assert_eq!(byte_copy_plan.len(), 1);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 1);
    let request = byte_copy_plan.requests()[0];
    assert_eq!(request.source(), child_address);
    assert_eq!(request.destination(), reservation.destination());
    assert_eq!(request.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(request.destination_generation(), HeapGeneration::Old);

    let report = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&byte_copy_plan)
        .expect("paired body/generation writes apply");

    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    assert_eq!(
        heap_generation(&heap, reservation.destination_value()),
        HeapGeneration::Old
    );
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Thunk)
        .expect("promoted destination body is bound to source body");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_reserved_destination_records_ignore_dead_young_reservations() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let live = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("live thunk allocates");
    let dead = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("dead thunk allocates");
    let live_address = gc_address(live);
    let dead_address = gc_address(dead);
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");
    let live_reservation = reservations
        .reservations()
        .iter()
        .copied()
        .find(|reservation| reservation.source() == live_address)
        .expect("live source has a reservation");
    let dead_reservation = reservations
        .reservations()
        .iter()
        .copied()
        .find(|reservation| reservation.source() == dead_address)
        .expect("dead source has a reservation");

    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("destination reservation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, live)
        .expect("live root records");
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
        .plan_collector_poll_minor_gc_reserved_relocation_destinations(&planned, &reservations)
        .expect("reserved destinations plan");

    assert_eq!(reservations.len(), 2);
    assert_eq!(destinations.destinations().len(), 1);
    assert_eq!(
        destinations.destinations()[0],
        MinorGcRelocationDestination::new(live_address, live_reservation.destination())
    );
    assert_ne!(
        destinations.destinations()[0].destination(),
        dead_reservation.destination()
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_reserved_destination_records_reject_stale_reservation_snapshot() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");
    let sibling = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("post-reservation sibling allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("post-reservation allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    roots
        .try_push_value_stack(1, sibling)
        .expect("sibling root records");
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

    assert_eq!(
        heap.plan_collector_poll_minor_gc_reserved_relocation_destinations(
            &planned,
            &reservations,
        )
        .expect_err("stale reservations reject"),
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation heap record count differs from minor-GC plan",
            expected_records: planned.heap_records(),
            actual_records: reservations.heap_records(),
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
fn collector_poll_minor_gc_object_byte_copy_plan_partitions_mixed_actions() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let first_copy = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first copied thunk allocates");
    let promote = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("promoted thunk allocates");
    let second_copy = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("second copied thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let first_copy_address = gc_address(first_copy);
    let promote_address = gc_address(promote);
    let second_copy_address = gc_address(second_copy);
    let roots = vec![
        ResolvedValueGeneration::young(first_copy_address),
        ResolvedValueGeneration::young(promote_address),
        ResolvedValueGeneration::young(second_copy_address),
    ];
    let nursery_objects = vec![
        NurseryObjectAge::new(first_copy_address, 0),
        NurseryObjectAge::new(promote_address, 1),
        NurseryObjectAge::new(second_copy_address, 0),
    ];
    let remembered_set = RememberedSet::new();
    let plan = MinorGcPlan::from_roots_and_remembered(
        roots.iter().copied(),
        remembered_set.snapshot(),
        remembered_set.epoch(),
        &nursery_objects,
        MinorGcPromotionPolicy::new(2),
    )
    .expect("mixed-action minor-GC plan builds");
    let planned = AllocationCollectorPollMinorGcPlan::from_parts_for_test(
        poll,
        heap.records.len(),
        heap.region_owner,
        heap.worker_region_epoch,
        heap.allocation_safepoints(),
        heap.permanent_allocation_safepoints(),
        remembered_set,
        roots,
        nursery_objects,
        Vec::new(),
        Vec::new(),
        plan,
    );
    let first_copy_size = record_layout_size(&heap, first_copy);
    let promote_size = record_layout_size(&heap, promote);
    let second_copy_size = record_layout_size(&heap, second_copy);
    let nursery_layouts = [
        NurseryObjectLayout::new(
            first_copy_address,
            first_copy_size,
            record_layout_align(&heap, first_copy),
        ),
        NurseryObjectLayout::new(
            promote_address,
            promote_size,
            record_layout_align(&heap, promote),
        ),
        NurseryObjectLayout::new(
            second_copy_address,
            second_copy_size,
            record_layout_align(&heap, second_copy),
        ),
    ];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("mixed-action destination plan builds");
    let commit = planned
        .commit_plan(&destinations)
        .expect("mixed-action commit plan builds");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("mixed-action object byte-copy plan derives");

    assert_eq!(byte_copy_plan.len(), 3);
    assert_eq!(byte_copy_plan.copy_to_nursery_count(), 2);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 1);
    assert_eq!(
        byte_copy_plan.copy_to_nursery_bytes(),
        first_copy_size + second_copy_size
    );
    assert_eq!(byte_copy_plan.promote_to_old_bytes(), promote_size);
    assert_eq!(
        byte_copy_plan
            .requests()
            .iter()
            .map(AllocationCollectorPollObjectByteCopyRequest::action)
            .collect::<Vec<_>>(),
        vec![
            MinorGcSurvivorAction::CopyToNursery,
            MinorGcSurvivorAction::PromoteToOld,
            MinorGcSurvivorAction::CopyToNursery,
        ]
    );
    let requests = byte_copy_plan.requests();
    assert_eq!(
        requests
            .iter()
            .map(AllocationCollectorPollObjectByteCopyRequest::source)
            .collect::<Vec<_>>(),
        vec![first_copy_address, promote_address, second_copy_address]
    );
    assert_eq!(requests[0].destination_generation(), HeapGeneration::Young);
    assert_eq!(requests[1].destination_generation(), HeapGeneration::Old);
    assert_eq!(requests[2].destination_generation(), HeapGeneration::Young);
    assert_eq!(
        byte_copy_plan
            .copy_to_nursery_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![requests[0], requests[2]]
    );
    assert_eq!(
        byte_copy_plan
            .promote_to_old_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![requests[1]]
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_relocation_destinations_reject_post_plan_allocation() {
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
    let expected_records = planned.heap_records();

    heap.alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("post-plan thunk allocates");

    assert_eq!(
        heap.plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect_err("post-plan allocation is rejected"),
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "heap record count changed since minor-GC planning",
            expected_records,
            actual_records: expected_records + 1,
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
fn collector_poll_minor_gc_object_byte_copy_plan_rejects_post_commit_allocation() {
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
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let expected_records = commit.heap_records();

    heap.alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("post-commit thunk allocates");

    assert_eq!(
        heap.collector_poll_minor_gc_object_byte_copy_plan(&commit)
            .expect_err("post-commit allocation is rejected"),
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "heap record count changed since minor-GC commit planning",
            expected_records,
            actual_records: expected_records + 1,
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
fn collector_poll_minor_gc_object_byte_copy_plan_rejects_stale_source_layout() {
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
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let expected_size = commit.commit_plan().object_copies().copies()[0].size_bytes();
    let expected_align = commit.commit_plan().object_copies().copies()[0].align();
    let actual_size = expected_size + 8;
    let child_address = gc_address(child);
    let record = heap
        .records
        .iter_mut()
        .find(|record| record.ptr.as_ptr() as usize == child_address.address_bits())
        .expect("child record exists");
    record.layout.size_bytes = actual_size;

    assert_eq!(
        heap.collector_poll_minor_gc_object_byte_copy_plan(&commit)
            .expect_err("stale source layout is rejected"),
        EvalHeapError::CollectorPollObjectByteCopyLayoutMismatch {
            address: child_address,
            expected_size,
            actual_size,
            expected_align,
            actual_align: expected_align,
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
fn collector_poll_minor_gc_destination_plan_uses_old_base_for_promotions() {
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
            MinorGcPromotionPolicy::new(0),
        )
        .expect("minor-GC plan builds");

    let old_base = static_gc_address(0x3000_0000);
    let nursery_layouts = [NurseryObjectLayout::new(gc_address(child), 24, 8)];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), old_base),
        )
        .expect("destination plan builds");

    assert_eq!(destinations.allocation_plan().nursery_bytes(), 0);
    assert_eq!(destinations.allocation_plan().old_bytes(), 24);
    assert_eq!(destinations.placement_plan().nursery_reserved_bytes(), 0);
    assert_eq!(destinations.placement_plan().old_reserved_bytes(), 24);
    assert_eq!(destinations.destinations().len(), 1);
    assert_eq!(destinations.destinations()[0].destination(), old_base);
    let relocation_plan = destinations
        .relocation_destinations()
        .relocation_plan(planned.plan())
        .expect("relocation plan rebuilds");
    assert_eq!(
        relocation_plan.relocations()[0].destination_generation(),
        HeapGeneration::Old
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].destination_generation(),
        HeapGeneration::Old
    );
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("promoted object byte-copy plan derives");
    assert_eq!(byte_copy_plan.len(), 1);
    assert_eq!(byte_copy_plan.copy_to_nursery_count(), 0);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 1);
    assert_eq!(byte_copy_plan.copy_to_nursery_bytes(), 0);
    assert_eq!(byte_copy_plan.promote_to_old_bytes(), 24);
    let byte_copy = &byte_copy_plan.requests()[0];
    assert_eq!(byte_copy.source(), gc_address(child));
    assert_eq!(byte_copy.destination(), old_base);
    assert_eq!(byte_copy.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(byte_copy.destination_generation(), HeapGeneration::Old);
    assert_eq!(byte_copy.size_bytes(), 24);
    assert_eq!(byte_copy.align(), 8);
    assert_eq!(
        byte_copy_plan
            .copy_to_nursery_requests()
            .copied()
            .collect::<Vec<_>>(),
        Vec::new()
    );
    assert_eq!(
        byte_copy_plan
            .promote_to_old_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![*byte_copy]
    );
    let mut forwarding_slots = commit
        .forwarding_slot_buffer()
        .expect("promoted forwarding slot buffer derives");
    assert_eq!(
        forwarding_slots,
        vec![MinorGcForwardingSlot::new(gc_address(child))]
    );
    commit
        .commit_plan()
        .forwarding_pointers()
        .install_into_slots(&mut forwarding_slots)
        .expect("promoted forwarding slot installs");
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: old_base,
            generation: HeapGeneration::Old,
        })
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_object_generation_writes_update_existing_destination_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    // Since FV-2 no allocation path creates a permanent record, so the
    // destination fixture manufactures one: a worker record flipped to the
    // permanent-shared domain.
    let destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("destination fixture thunk allocates");
    heap.set_allocation_domain_for_test(destination, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("source thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, source)
        .expect("source root records");
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
            MinorGcDestinationBases::new(gc_address(destination), static_gc_address(0x2000_0000)),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    let generation_write_plan = byte_copy_plan
        .object_generation_write_plan()
        .expect("generation write plan derives");

    assert_eq!(generation_write_plan.len(), 1);
    assert!(!generation_write_plan.is_empty());
    assert_eq!(generation_write_plan.report().objects(), 1);
    assert_eq!(generation_write_plan.report().copied_to_nursery(), 1);
    assert_eq!(generation_write_plan.report().promoted_to_old(), 0);
    assert_eq!(
        generation_write_plan.report().payload_bytes(),
        record_layout_size(&heap, source)
    );
    assert_eq!(
        generation_write_plan.writes()[0].source(),
        gc_address(source)
    );
    assert_eq!(
        generation_write_plan.writes()[0].destination(),
        gc_address(destination)
    );
    assert_eq!(
        generation_write_plan.writes()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        generation_write_plan.writes()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        heap_generation(&heap, destination),
        HeapGeneration::Permanent
    );

    let report = heap
        .apply_collector_poll_minor_gc_object_generation_writes(&generation_write_plan)
        .expect("generation writes apply");

    assert_eq!(report, generation_write_plan.report());
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert_eq!(
        allocation_domain(&heap, destination),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(heap_generation(&heap, source), HeapGeneration::Young);
}
