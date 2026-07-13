//! Evaluator-heap unit tests, part 6 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_plan_tracks_worker_survivor_frontier() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let sibling = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("sibling thunk allocates");
    let frame = EvalFrame::new(2).expect("frame allocates");
    frame.set(0, child).expect("slot writes");
    frame.set(1, sibling).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            env,
        ))
        .expect("lambda allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, lambda)
        .expect("lambda root records");
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

    assert_eq!(planned.poll(), poll);
    assert_eq!(
        planned.roots(),
        &[ResolvedValueGeneration::Heap {
            address: gc_address(lambda),
            generation: HeapGeneration::Young,
        }]
    );
    assert_eq!(planned.nursery_objects().len(), 3);
    assert_eq!(planned.nursery_fields().len(), 3);
    let lambda_fields = planned
        .nursery_fields()
        .iter()
        .find(|fields| fields.address() == gc_address(lambda))
        .expect("lambda field metadata records");
    assert_eq!(lambda_fields.fields().len(), 2);
    assert_eq!(
        lambda_fields.fields()[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Lambda,
            frame: 0,
            slot: 0,
        }
    );
    assert_eq!(
        lambda_fields.fields()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        lambda_fields.fields()[1].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Lambda,
            frame: 0,
            slot: 1,
        }
    );
    assert_eq!(
        lambda_fields.fields()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(sibling),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(planned.plan().survivors().len(), 3);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(lambda));
    assert_eq!(planned.plan().survivors()[1].address(), gc_address(child));
    assert_eq!(planned.plan().survivors()[2].address(), gc_address(sibling));
    assert_eq!(planned.reference_slots().len(), 3);
    assert_eq!(
        planned.reference_slots()[0].source(),
        &AllocationCollectorPollReferenceSource::Root {
            source: EvalRootSource::ValueStack { slot: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(lambda),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::NurseryField {
            object: gc_address(lambda),
            field_index: 0,
            source: HeapEdgeSource::CapturedEnv {
                owner: CapturedRootOwner::Lambda,
                frame: 0,
                slot: 0,
            },
        }
    );
    assert_eq!(
        planned.reference_slots()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        planned.reference_slots()[2].source(),
        &AllocationCollectorPollReferenceSource::NurseryField {
            object: gc_address(lambda),
            field_index: 1,
            source: HeapEdgeSource::CapturedEnv {
                owner: CapturedRootOwner::Lambda,
                frame: 0,
                slot: 1,
            },
        }
    );
    assert_eq!(
        planned.reference_slots()[2].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(sibling),
            generation: HeapGeneration::Young,
        }
    );

    let nursery_layouts = [
        NurseryObjectLayout::new(gc_address(lambda), 16, 8),
        NurseryObjectLayout::new(gc_address(child), 16, 8),
        NurseryObjectLayout::new(gc_address(sibling), 16, 8),
    ];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan builds");
    assert_eq!(destinations.allocation_plan().nursery_bytes(), 48);
    assert_eq!(destinations.allocation_plan().old_bytes(), 0);
    assert_eq!(destinations.placement_plan().nursery_reserved_bytes(), 48);
    assert_eq!(destinations.placement_plan().old_reserved_bytes(), 0);
    assert_eq!(destinations.destinations().len(), 3);
    let lambda_destination = destinations.destinations()[0].destination();
    let child_destination = destinations.destinations()[1].destination();
    let sibling_destination = destinations.destinations()[2].destination();
    assert_eq!(lambda_destination, static_gc_address(0x1000_0000));
    assert_eq!(child_destination, static_gc_address(0x1000_0010));
    assert_eq!(sibling_destination, static_gc_address(0x1000_0020));
    let relocation_destinations = destinations.destinations();
    let relocation_plan =
        MinorGcRelocationPlan::from_minor_gc_plan(planned.plan(), relocation_destinations)
            .expect("relocation plan builds");
    let rewrite_plan = planned
        .reference_rewrite_plan(&relocation_plan)
        .expect("reference rewrite plan builds");
    assert_eq!(rewrite_plan.rewrites().len(), 3);
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 0);
    assert_eq!(rewrite_plan.rewrites()[0].source(), gc_address(lambda));
    assert_eq!(rewrite_plan.rewrites()[0].destination(), lambda_destination);
    assert_eq!(rewrite_plan.rewrites()[1].slot(), 1);
    assert_eq!(rewrite_plan.rewrites()[1].source(), gc_address(child));
    assert_eq!(rewrite_plan.rewrites()[1].destination(), child_destination);
    assert_eq!(rewrite_plan.rewrites()[2].slot(), 2);
    assert_eq!(rewrite_plan.rewrites()[2].source(), gc_address(sibling));
    assert_eq!(
        rewrite_plan.rewrites()[2].destination(),
        sibling_destination
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    assert_eq!(commit.reference_slots(), planned.reference_slots());
    assert_eq!(commit.commit_plan().object_copies().copies().len(), 3);
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].source(),
        gc_address(lambda)
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].destination(),
        lambda_destination
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[1].source(),
        gc_address(child)
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[1].destination(),
        child_destination
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[2].source(),
        gc_address(sibling)
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[2].destination(),
        sibling_destination
    );
    assert_eq!(
        commit.commit_plan().forwarding_pointers().pointers().len(),
        3
    );
    assert_eq!(
        commit
            .forwarding_slot_buffer()
            .expect("forwarding slot buffer derives"),
        vec![
            MinorGcForwardingSlot::new(gc_address(lambda)),
            MinorGcForwardingSlot::new(gc_address(child)),
            MinorGcForwardingSlot::new(gc_address(sibling)),
        ]
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites(),
        rewrite_plan.rewrites()
    );
    assert!(commit.commit_plan().remembered_set_refresh().is_empty());
    assert_eq!(
        commit.commit_plan().next_remembered_set().epoch(),
        remembered_set
            .epoch()
            .checked_next()
            .expect("epoch advances")
    );
    assert!(commit.commit_plan().next_remembered_set().is_empty());

    let short_commit = planned
        .commit_plan(&destinations)
        .expect("short-buffer commit plan builds");
    let mut no_object_byte_copies: Vec<MinorGcObjectByteCopyBuffer<'_>> = Vec::new();
    let mut no_forwarding_slots = Vec::new();
    let mut short_references = [planned.reference_slots()[0].value()];
    let mut short_remembered_set = remembered_set.clone();
    assert_eq!(
        short_commit
            .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
                &mut no_object_byte_copies,
                &mut no_forwarding_slots,
                &mut short_references,
                &mut short_remembered_set,
            ))
            .expect_err("short reference buffer is rejected before lower-level buffers"),
        EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
            expected: planned.reference_slots().len(),
            actual: short_references.len(),
        }
    );
    assert_eq!(short_references, [planned.reference_slots()[0].value()]);
    assert_eq!(short_remembered_set, remembered_set);

    let occupied_commit = planned
        .commit_plan(&destinations)
        .expect("occupied-slot commit plan builds");
    let occupied_lambda_source_bytes = [9u8; 16];
    let occupied_child_source_bytes = [8u8; 16];
    let occupied_sibling_source_bytes = [7u8; 16];
    let mut occupied_lambda_destination_bytes = [0u8; 16];
    let mut occupied_child_destination_bytes = [0u8; 16];
    let mut occupied_sibling_destination_bytes = [0u8; 16];
    let mut occupied_object_byte_copies = [
        MinorGcObjectByteCopyBuffer::new(
            gc_address(lambda),
            lambda_destination,
            &occupied_lambda_source_bytes,
            &mut occupied_lambda_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(child),
            child_destination,
            &occupied_child_source_bytes,
            &mut occupied_child_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(sibling),
            sibling_destination,
            &occupied_sibling_source_bytes,
            &mut occupied_sibling_destination_bytes,
        ),
    ];
    let occupied_forwarded_value = ResolvedValueGeneration::Heap {
        address: lambda_destination,
        generation: HeapGeneration::Young,
    };
    let mut occupied_forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(lambda), occupied_forwarded_value),
        MinorGcForwardingSlot::new(gc_address(child)),
        MinorGcForwardingSlot::new(gc_address(sibling)),
    ];
    let mut occupied_references = planned.reference_values().collect::<Vec<_>>();
    let mut occupied_remembered_set = remembered_set.clone();
    assert_eq!(
        occupied_commit
            .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
                &mut occupied_object_byte_copies,
                &mut occupied_forwarding_slots,
                &mut occupied_references,
                &mut occupied_remembered_set,
            ))
            .expect_err("occupied forwarding slot is rejected"),
        EvalHeapError::GenerationalGc(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
            index: 0,
            address: gc_address(lambda),
            actual: occupied_forwarded_value,
        })
    );
    assert_eq!(occupied_lambda_destination_bytes, [0u8; 16]);
    assert_eq!(occupied_child_destination_bytes, [0u8; 16]);
    assert_eq!(occupied_sibling_destination_bytes, [0u8; 16]);
    assert_eq!(
        occupied_forwarding_slots[0].forwarded_value(),
        Some(occupied_forwarded_value)
    );
    assert!(occupied_forwarding_slots[1].is_empty());
    assert!(occupied_forwarding_slots[2].is_empty());
    assert_eq!(
        occupied_references,
        planned.reference_values().collect::<Vec<_>>()
    );
    assert_eq!(occupied_remembered_set, remembered_set);

    let expected_next_remembered_set = commit.commit_plan().next_remembered_set().clone();
    let lambda_source_bytes = [1u8; 16];
    let child_source_bytes = [2u8; 16];
    let sibling_source_bytes = [3u8; 16];
    let mut lambda_destination_bytes = [0u8; 16];
    let mut child_destination_bytes = [0u8; 16];
    let mut sibling_destination_bytes = [0u8; 16];
    let mut object_byte_copies = [
        MinorGcObjectByteCopyBuffer::new(
            gc_address(lambda),
            lambda_destination,
            &lambda_source_bytes,
            &mut lambda_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(child),
            child_destination,
            &child_source_bytes,
            &mut child_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(sibling),
            sibling_destination,
            &sibling_source_bytes,
            &mut sibling_destination_bytes,
        ),
    ];
    let mut forwarding_slots = commit
        .forwarding_slot_buffer()
        .expect("success forwarding slot buffer derives");
    let mut references = planned.reference_values().collect::<Vec<_>>();
    let mut commit_remembered_set = remembered_set.clone();

    let report = commit
        .apply_to_buffers_with_report(AllocationCollectorPollMinorGcCommitBuffers::new(
            &mut object_byte_copies,
            &mut forwarding_slots,
            &mut references,
            &mut commit_remembered_set,
        ))
        .expect("collector-poll commit buffers apply");

    assert_eq!(report.object_copies(), 3);
    assert_eq!(report.copied_to_nursery(), 3);
    assert_eq!(report.promoted_to_old(), 0);
    assert_eq!(report.forwarding_pointers(), 3);
    assert_eq!(report.reference_rewrites(), 3);
    assert_eq!(report.remembered_set_source_epoch(), remembered_set.epoch());
    assert_eq!(
        report.remembered_set_next_epoch(),
        remembered_set
            .epoch()
            .checked_next()
            .expect("epoch advances")
    );
    assert_eq!(report.remembered_set_source_edges(), 0);
    assert_eq!(report.remembered_set_published_edges(), 0);
    assert_eq!(lambda_destination_bytes, lambda_source_bytes);
    assert_eq!(child_destination_bytes, child_source_bytes);
    assert_eq!(sibling_destination_bytes, sibling_source_bytes);
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: lambda_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        forwarding_slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        forwarding_slots[2].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: sibling_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        references,
        vec![
            ResolvedValueGeneration::Heap {
                address: lambda_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: child_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: sibling_destination,
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(commit_remembered_set, expected_next_remembered_set);

    let mut owned_destination_storage =
        MinorGcOwnedDestinationStorage::from_placement_plan(destinations.placement_plan())
            .expect("owned destination storage allocates");
    let owned_destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            owned_destination_storage.destination_bases(),
        )
        .expect("owned-storage destination plan builds");
    let owned_lambda_destination = owned_destinations.destinations()[0].destination();
    let owned_child_destination = owned_destinations.destinations()[1].destination();
    let owned_sibling_destination = owned_destinations.destinations()[2].destination();
    let owned_commit = planned
        .commit_plan(&owned_destinations)
        .expect("owned-storage commit plan builds");
    let owned_source_bytes = [
        MinorGcSourceObjectBytes::new(gc_address(lambda), &lambda_source_bytes),
        MinorGcSourceObjectBytes::new(gc_address(child), &child_source_bytes),
        MinorGcSourceObjectBytes::new(gc_address(sibling), &sibling_source_bytes),
    ];
    let mut owned_forwarding_slots = owned_commit
        .forwarding_slot_buffer()
        .expect("owned forwarding slot buffer derives");
    let mut owned_references = planned.reference_values().collect::<Vec<_>>();
    let mut owned_remembered_set = remembered_set.clone();
    let expected_owned_next_remembered_set =
        owned_commit.commit_plan().next_remembered_set().clone();
    let mut owned_card_table = GcCardTable::new(0x1000).expect("owned card table builds");
    owned_card_table
        .mark_source(gc_address(lambda))
        .expect("owned card marks");

    let owned_report = owned_commit
        .apply_to_owned_destination_storage_with_report(
            AllocationCollectorPollMinorGcOwnedCommitBuffers::with_card_table(
                &mut owned_destination_storage,
                &owned_source_bytes,
                &mut owned_forwarding_slots,
                &mut owned_references,
                &mut owned_remembered_set,
                &mut owned_card_table,
            ),
        )
        .expect("collector-poll owned destination storage applies");

    assert_eq!(owned_report.object_copies(), 3);
    assert_eq!(owned_report.copied_to_nursery(), 3);
    assert_eq!(owned_report.promoted_to_old(), 0);
    assert_eq!(owned_report.card_table_dirty_cards_cleared(), 1);
    let mut expected_owned_nursery_bytes = Vec::new();
    expected_owned_nursery_bytes.extend_from_slice(&lambda_source_bytes);
    expected_owned_nursery_bytes.extend_from_slice(&child_source_bytes);
    expected_owned_nursery_bytes.extend_from_slice(&sibling_source_bytes);
    assert_eq!(
        owned_destination_storage.nursery_destination_bytes(),
        expected_owned_nursery_bytes.as_slice()
    );
    assert!(owned_destination_storage.old_destination_bytes().is_empty());
    assert_eq!(
        owned_forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: owned_lambda_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        owned_forwarding_slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: owned_child_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        owned_forwarding_slots[2].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: owned_sibling_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        owned_references,
        vec![
            ResolvedValueGeneration::Heap {
                address: owned_lambda_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: owned_child_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: owned_sibling_destination,
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(owned_remembered_set, expected_owned_next_remembered_set);
    assert!(owned_card_table.is_empty());

    let mut stale_destination_storage =
        MinorGcOwnedDestinationStorage::from_placement_plan(destinations.placement_plan())
            .expect("stale owned destination storage allocates");
    let stale_destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            stale_destination_storage.destination_bases(),
        )
        .expect("stale owned-storage destination plan builds");
    let stale_commit = planned
        .commit_plan(&stale_destinations)
        .expect("stale owned-storage commit plan builds");
    let mut stale_forwarding_slots = stale_commit
        .forwarding_slot_buffer()
        .expect("stale forwarding slot buffer derives");
    let mut stale_references = planned.reference_values().collect::<Vec<_>>();
    let expected_stale_reference = stale_references[1];
    stale_references[1] = ResolvedValueGeneration::Inline;
    let mut stale_remembered_set = remembered_set.clone();
    let unchanged_stale_references = stale_references.clone();

    assert_eq!(
        stale_commit
            .apply_to_owned_destination_storage(
                AllocationCollectorPollMinorGcOwnedCommitBuffers::new(
                    &mut stale_destination_storage,
                    &owned_source_bytes,
                    &mut stale_forwarding_slots,
                    &mut stale_references,
                    &mut stale_remembered_set,
                )
            )
            .expect_err("stale reference buffer is rejected before owned storage mutates"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: expected_stale_reference,
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(
        stale_destination_storage.nursery_destination_bytes(),
        vec![0u8; expected_owned_nursery_bytes.len()].as_slice()
    );
    assert!(stale_forwarding_slots.iter().all(|slot| slot.is_empty()));
    assert_eq!(stale_references, unchanged_stale_references);
    assert_eq!(stale_remembered_set, remembered_set);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_forwarding_install_writes_valid_slots() {
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
    let second_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(second), second_forwarded),
    ];

    let report = heap
        .install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
        .expect("forwarding slots install");
    let forwarding_values = heap
        .minor_gc_forwarding_values()
        .expect("forwarding values snapshot builds");

    assert_eq!(report.forwarding_pointers(), 2);
    assert_eq!(forwarding_values.len(), 2);
    assert_eq!(forwarding_values[0].source(), gc_address(first));
    assert_eq!(forwarding_values[0].forwarded_value(), first_forwarded);
    assert_eq!(forwarding_values[1].source(), gc_address(second));
    assert_eq!(forwarding_values[1].forwarded_value(), second_forwarded);
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        Some(first_forwarded)
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(second))
            .expect("second forwarding source remains known"),
        Some(second_forwarded)
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_forwarding_install_rejects_empty_slot_without_partial_mutation() {
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
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::new(gc_address(second)),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("empty second forwarding slot is rejected"),
        EvalHeapError::CollectorPollForwardingSlotEmpty {
            index: 1,
            address: gc_address(second),
        }
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(second))
            .expect("second forwarding source remains known"),
        None
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_forwarding_install_rejects_duplicate_source_without_partial_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let duplicate_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), duplicate_forwarded),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("duplicate forwarding source is rejected"),
        EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
            index: 1,
            address: gc_address(first),
        }
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_forwarding_install_rejects_permanent_source_without_partial_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    // Since FV-2 no allocation path creates a permanent record (strings,
    // paths, lists, and attrsets are all flat), so the fixture manufactures
    // one: a worker record flipped to the permanent-shared domain.
    let permanent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("permanent-fixture thunk allocates");
    heap.set_allocation_domain_for_test(permanent, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let permanent_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(permanent), permanent_forwarded),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("permanent forwarding source is rejected"),
        EvalHeapError::GenerationalGc(GenerationalGcError::StaleNurseryObjectLayout {
            address: gc_address(permanent),
        })
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(permanent))
            .expect("permanent forwarding source remains known"),
        None
    );
}
