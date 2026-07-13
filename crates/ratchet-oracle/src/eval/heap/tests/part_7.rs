//! Evaluator-heap unit tests, part 7 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_forwarding_install_rejects_occupied_later_slot_without_partial_mutation()
{
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("second thunk allocates");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let second_initial_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let second_retry_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0020),
        generation: HeapGeneration::Young,
    };
    heap.install_collector_poll_minor_gc_forwarding_slots(&[
        MinorGcForwardingSlot::with_forwarded_value(gc_address(second), second_initial_forwarded),
    ])
    .expect("initial second forwarding slot installs");
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(second), second_retry_forwarded),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("occupied second forwarding source is rejected"),
        EvalHeapError::GenerationalGc(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
            index: 1,
            address: gc_address(second),
            actual: second_initial_forwarded,
        })
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(second))
            .expect("second forwarding source remains known"),
        Some(second_initial_forwarded)
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_keeps_hash_consed_roots_out_of_survivor_frontier() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("thunk allocates");
    let lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lambda allocates");
    let primop = heap
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("primop allocates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"hash-consed".to_vec()))
        .expect("string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(b"/nix/store/source".to_vec()))
        .expect("path allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(9, attrs_with_value(Value::int(3)))
        .expect("attrs allocates");
    let expected_cold_hash_consed_bytes = record_layout_size(&heap, string)
        + record_layout_size(&heap, path)
        + record_layout_size(&heap, list)
        + record_layout_size(&heap, attrs);
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    for (slot, value) in [string, path, list, attrs].into_iter().enumerate() {
        roots
            .try_push_value_stack(slot, value)
            .expect("hash-consed root records");
    }
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
        [string, path, list, attrs].map(|value| allocation_domain(&heap, value)),
        [HeapAllocationDomain::PermanentShared; 4]
    );
    assert_eq!(
        [thunk, lambda, primop].map(|value| allocation_domain(&heap, value)),
        [HeapAllocationDomain::Worker; 3]
    );
    assert_eq!(
        heap.cold_hash_consed_bytes(0),
        expected_cold_hash_consed_bytes
    );
    assert_eq!(
        planned.roots(),
        &[
            ResolvedValueGeneration::Heap {
                address: gc_address(string),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(path),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(list),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(attrs),
                generation: HeapGeneration::Permanent,
            },
        ]
    );
    assert!(planned.plan().survivors().is_empty());
    assert_eq!(planned.nursery_objects().len(), 3);
    assert!(
        planned
            .nursery_objects()
            .iter()
            .any(|object| object.address() == gc_address(thunk))
    );
    assert!(
        planned
            .nursery_objects()
            .iter()
            .any(|object| object.address() == gc_address(lambda))
    );
    assert!(
        planned
            .nursery_objects()
            .iter()
            .any(|object| object.address() == gc_address(primop))
    );
    assert_eq!(planned.reference_slots().len(), 4);
    assert!(planned.reference_slots().iter().all(|slot| matches!(
        slot.value(),
        ResolvedValueGeneration::Heap {
            generation: HeapGeneration::Permanent,
            ..
        }
    )));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_commit_plan_rejects_foreign_destination_plan() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
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
    let remembered_set = RememberedSet::new();
    let mut first_roots = EvalRootSet::new();
    first_roots
        .try_push_value_stack(0, first)
        .expect("first root records");
    let first_scan = heap
        .scan_collector_poll_roots(poll, &first_roots)
        .expect("first collector-poll root scan succeeds");
    let first_plan = heap
        .plan_collector_poll_minor_gc(
            &first_scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("first minor-GC plan builds");

    let mut second_roots = EvalRootSet::new();
    second_roots
        .try_push_value_stack(0, second)
        .expect("second root records");
    let second_scan = heap
        .scan_collector_poll_roots(poll, &second_roots)
        .expect("second collector-poll root scan succeeds");
    let second_plan = heap
        .plan_collector_poll_minor_gc(
            &second_scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("second minor-GC plan builds");
    let second_layouts = [NurseryObjectLayout::new(gc_address(second), 16, 8)];
    let second_destinations = second_plan
        .relocation_destination_plan(
            &second_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("second destination plan builds");

    assert_eq!(
        first_plan
            .commit_plan(&second_destinations)
            .expect_err("foreign destination plan is rejected"),
        GenerationalGcError::MinorGcRelocationDestinationPlacementSourceMismatch {
            expected: gc_address(first),
            actual: gc_address(second),
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
fn collector_poll_minor_gc_commit_plan_rejects_destination_plan_with_foreign_action() {
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
    let copy_plan = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("copy minor-GC plan builds");
    let promote_plan = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(0),
        )
        .expect("promote minor-GC plan builds");
    let copy_layouts = [NurseryObjectLayout::new(gc_address(child), 16, 8)];
    let copy_destinations = copy_plan
        .relocation_destination_plan(
            &copy_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("copy destination plan builds");

    assert_eq!(
        promote_plan
            .commit_plan(&copy_destinations)
            .expect_err("foreign-action destination plan is rejected"),
        GenerationalGcError::MinorGcRelocationDestinationPlacementActionMismatch {
            address: gc_address(child),
            expected: MinorGcSurvivorAction::PromoteToOld,
            actual: MinorGcSurvivorAction::CopyToNursery,
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
fn collector_poll_minor_gc_relocation_destinations_derive_layouts_from_heap_records() {
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

    let base = static_gc_address(0x1000_0000);
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(base, static_gc_address(0x2000_0000)),
        )
        .expect("destination plan derives heap layouts");
    let expected_thunk_bytes = std::mem::size_of::<u64>() * 3;
    let expected_align = std::mem::align_of::<u64>();

    assert_eq!(
        destinations.allocation_plan().nursery_bytes(),
        expected_thunk_bytes
    );
    assert_eq!(destinations.allocation_plan().old_bytes(), 0);
    assert_eq!(
        destinations.placement_plan().nursery_reserved_bytes(),
        expected_thunk_bytes
    );
    assert_eq!(destinations.destinations()[0].destination(), base);
    assert_eq!(
        destinations.placement_plan().placements()[0].align(),
        expected_align
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds from derived layouts");
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].size_bytes(),
        expected_thunk_bytes
    );
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    assert_eq!(byte_copy_plan.len(), 1);
    assert!(!byte_copy_plan.is_empty());
    assert_eq!(byte_copy_plan.copy_to_nursery_count(), 1);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 0);
    assert_eq!(byte_copy_plan.copy_to_nursery_bytes(), expected_thunk_bytes);
    assert_eq!(byte_copy_plan.promote_to_old_bytes(), 0);
    let byte_copy = &byte_copy_plan.requests()[0];
    assert_eq!(byte_copy.source(), gc_address(child));
    assert_eq!(byte_copy.destination(), base);
    assert_eq!(byte_copy.action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(byte_copy.destination_generation(), HeapGeneration::Young);
    assert_eq!(byte_copy.size_bytes(), expected_thunk_bytes);
    assert_eq!(byte_copy.align(), expected_align);
    assert_eq!(
        byte_copy_plan
            .copy_to_nursery_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![*byte_copy]
    );
    assert_eq!(
        byte_copy_plan
            .promote_to_old_requests()
            .copied()
            .collect::<Vec<_>>(),
        Vec::new()
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_accept_noncontiguous_addresses() {
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
    let first_destination = static_gc_address(0x5000_0000);
    let second_destination = static_gc_address(0x3000_0000);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(gc_address(second), second_destination),
        MinorGcRelocationDestination::new(gc_address(first), first_destination),
    ];

    let destinations = heap
        .plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect("explicit destinations plan");

    assert_eq!(destinations.destinations().len(), 2);
    assert_eq!(
        destinations.destinations()[0],
        MinorGcRelocationDestination::new(gc_address(first), first_destination)
    );
    assert_eq!(
        destinations.destinations()[1],
        MinorGcRelocationDestination::new(gc_address(second), second_destination)
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan accepts explicit destinations");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    assert_eq!(
        byte_copy_plan
            .requests()
            .iter()
            .map(AllocationCollectorPollObjectByteCopyRequest::destination)
            .collect::<Vec<_>>(),
        vec![first_destination, second_destination]
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_duplicate_destination() {
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
    let destination = static_gc_address(0x5000_0000);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(gc_address(first), destination),
        MinorGcRelocationDestination::new(gc_address(second), destination),
    ];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("duplicate explicit destination rejects"),
        EvalHeapError::GenerationalGc(GenerationalGcError::DuplicateMinorGcRelocationDestination {
            address: destination,
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
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_overlapping_ranges() {
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
    let first_destination = static_gc_address(0x5000_0000);
    let second_destination = static_gc_address(0x5000_0008);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(gc_address(first), first_destination),
        MinorGcRelocationDestination::new(gc_address(second), second_destination),
    ];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("overlapping explicit destination ranges reject"),
        EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: first_destination,
                second_generation: HeapGeneration::Young,
                second: second_destination,
            }
        )
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_cross_generation_overlap() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let copy = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("copied thunk allocates");
    let promote = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("promoted thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let copy_address = gc_address(copy);
    let promote_address = gc_address(promote);
    let roots = vec![
        ResolvedValueGeneration::young(copy_address),
        ResolvedValueGeneration::young(promote_address),
    ];
    let nursery_objects = vec![
        NurseryObjectAge::new(copy_address, 0),
        NurseryObjectAge::new(promote_address, 1),
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
    let copy_destination = static_gc_address(0x5000_0000);
    let promote_destination = static_gc_address(0x5000_0008);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(copy_address, copy_destination),
        MinorGcRelocationDestination::new(promote_address, promote_destination),
    ];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("cross-generation explicit destination ranges reject"),
        EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: copy_destination,
                second_generation: HeapGeneration::Old,
                second: promote_destination,
            }
        )
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_source_range_overlap() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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
    let child_address = gc_address(child);
    let destination = static_gc_address(child_address.address_bits() + 8);
    let explicit_destinations = [MinorGcRelocationDestination::new(
        child_address,
        destination,
    )];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("from-space interior explicit destination rejects"),
        EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcObjectCopyDestinationSourceRangeOverlap {
                source_address: child_address,
                destination,
            }
        )
    );
}
