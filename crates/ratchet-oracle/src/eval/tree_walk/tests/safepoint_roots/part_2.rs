//! Split-out tests (part_2). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_reference_writeback_plan_reports_mixed_partitions() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_epoch = evaluator.thunk_resolve_remembered_set().epoch();
    let next_epoch = source_epoch
        .checked_next()
        .expect("remembered-set epoch advances");
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives");

    assert_eq!(plan.poll(), poll);
    assert_eq!(plan.scanned_roots(), 4);
    assert_eq!(plan.scanned_objects(), 2);
    assert_eq!(plan.survivors(), 1);
    assert_eq!(plan.reference_slots(), 5);
    assert_eq!(plan.destination_placements(), 1);
    assert_eq!(
        plan.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        plan.nursery_reserved_bytes(),
        plan.object_body_plan().requests()[0].size_bytes()
    );
    assert_eq!(plan.old_reserved_bytes(), 0);
    assert_eq!(plan.total_reserved_bytes(), plan.nursery_reserved_bytes());
    assert_eq!(plan.source_remembered_set().epoch(), source_epoch);
    assert_eq!(plan.source_remembered_set_edges(), 1);
    assert_eq!(
        plan.source_remembered_set().edges(),
        &[RememberedEdge::new(gc_address(parent), gc_address(child))]
    );
    assert_eq!(plan.source_dirty_cards(), 1);
    assert!(
        plan.source_card_table()
            .snapshot()
            .covers_source(gc_address(parent))
    );
    assert_eq!(plan.remembered_set_refreshes(), 1);
    assert_eq!(plan.next_remembered_set().epoch(), next_epoch);
    assert_eq!(plan.next_remembered_set_edges(), 1);
    assert_eq!(
        plan.next_remembered_set().edges(),
        &[RememberedEdge::new(gc_address(parent), nursery_base)]
    );
    assert_eq!(plan.writebacks().len(), 4);
    assert_eq!(plan.root_writebacks(), 3);
    assert_eq!(plan.heap_field_writebacks(), 1);
    let root_sources: Vec<_> = plan
        .writebacks()
        .root_writebacks()
        .writebacks()
        .iter()
        .map(|writeback| writeback.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    let heap_field_writebacks = plan.writebacks().heap_field_writebacks().writebacks();
    assert_eq!(heap_field_writebacks.len(), 1);
    let heap_writeback = &heap_field_writebacks[0];
    assert_eq!(heap_writeback.slot(), 4);
    assert_eq!(heap_writeback.validation_object(), gc_address(parent));
    assert_eq!(heap_writeback.writeback_object(), gc_address(parent));
    assert_eq!(heap_writeback.field_index(), 0);
    assert_eq!(
        heap_writeback.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_writeback.expected(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap_writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert_raw_eq(value_stack[0], child);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_reference_writebacks_apply_to_safepoint_buffers_mixed_partitions() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writebacks apply to buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 4);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 5);
    assert_eq!(application.root_writebacks(), 3);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.applied_heap_field_writebacks(), 1);
    assert_eq!(application.applied_writebacks(), 4);
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    let root_sources: Vec<_> = application
        .root_value_writeback_slots()
        .iter()
        .map(|slot| slot.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }

    let heap_field_slots = application.heap_field_writeback_slots();
    assert_eq!(heap_field_slots.len(), 1);
    let heap_slot = &heap_field_slots[0];
    assert_eq!(heap_slot.validation_object(), gc_address(parent));
    assert_eq!(heap_slot.writeback_object(), gc_address(parent));
    assert_eq!(heap_slot.field_index(), 0);
    assert_eq!(
        heap_slot.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_slot.value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_apply_root_storage_after_field_buffer_validation() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
        )
        .expect("mixed reference writebacks apply to roots and field buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 4);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 5);
    assert_eq!(application.root_writebacks(), 3);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.applied_heap_field_writebacks(), 1);
    assert_eq!(application.applied_writebacks(), 4);
    assert_eq!(application.buffers().applied_writebacks(), 4);
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }

    let heap_field_slots = application.heap_field_writeback_slots();
    assert_eq!(heap_field_slots.len(), 1);
    assert_eq!(heap_field_slots[0].validation_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].writeback_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].field_index(), 0);
    assert_eq!(
        heap_field_slots[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_field_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_apply_root_storage_and_field_buffers_with_primop_arguments() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let mut primop_arguments = vec![child];
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("mixed primop reference writebacks apply to roots and field buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 5);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 6);
    assert_eq!(application.root_writebacks(), 4);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.applied_heap_field_writebacks(), 1);
    assert_eq!(application.applied_writebacks(), 5);
    assert_eq!(application.buffers().applied_writebacks(), 5);
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    let root_sources: Vec<_> = application
        .root_value_writeback_slots()
        .iter()
        .map(|slot| slot.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(root_sources.contains(&&EvalRootSource::PrimopArgument { index: 0 }));
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }

    let heap_field_slots = application.heap_field_writeback_slots();
    assert_eq!(heap_field_slots.len(), 1);
    assert_eq!(heap_field_slots[0].validation_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].writeback_object(), gc_address(parent));
    assert_eq!(heap_field_slots[0].field_index(), 0);
    assert_eq!(
        heap_field_slots[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_field_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_root_storage_reject_late_frame_borrow_before_partial_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("reference writeback plan derives for supported roots");
    let suspended_frame = evaluator.suspended_env_roots[0].env[0].clone();
    let _held_frame_borrow = suspended_frame
        .borrow_slots_for_test()
        .expect("test holds suspended frame borrow");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            &plan,
            &mut value_stack,
        )
        .expect_err("held later frame borrow rejects before root mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Environment(EvalEnvError::BorrowConflict)
    );
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_validate_existing_destination_without_mutation() {
    let (evaluator, child, parent, destination, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    let original_destination_pattern = destination_lambda.pattern();
    let original_destination_body = destination_lambda.body();
    let original_destination_frame = destination_lambda.frame();
    let original_destination_generation = evaluator
        .heap()
        .generation(destination)
        .expect("destination starts heap-bound");
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    assert_eq!(plan.object_bodies(), 1);
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), gc_address(child));
    assert_eq!(request.destination(), destination_address);

    let preflight = evaluator
        .validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            &plan,
            &value_stack,
        )
        .expect("mixed reference writebacks validate without mutation");
    let derived_preflight = evaluator
        .validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("poll-derived mixed reference writebacks validate without mutation");
    assert_eq!(derived_preflight, preflight);

    assert_eq!(preflight.poll(), poll);
    assert_eq!(preflight.scanned_roots(), 4);
    assert_eq!(preflight.scanned_objects(), 2);
    assert_eq!(preflight.survivors(), 1);
    assert_eq!(preflight.reference_slots(), 5);
    assert_eq!(preflight.root_writebacks(), 3);
    assert_eq!(preflight.heap_field_writebacks(), 1);
    assert_eq!(preflight.object_bodies_preflighted(), 1);
    assert_eq!(preflight.object_generations_preflighted(), 1);
    assert_eq!(preflight.validated_root_writebacks(), 3);
    assert_eq!(preflight.live_heap_field_writebacks(), 1);
    assert_eq!(preflight.validated_live_writebacks(), 4);
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in preflight.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_eq!(preflight.heap_field_writeback_slots().len(), 1);
    assert_eq!(
        resolved_heap_destination_address(preflight.heap_field_writeback_slots()[0].value()),
        Some(destination_address)
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, child);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        child,
    );
    let destination_lambda = evaluator
        .heap()
        .get_lambda(destination)
        .expect("scratch destination remains a lambda");
    assert_eq!(destination_lambda.pattern(), original_destination_pattern);
    assert_eq!(destination_lambda.body(), original_destination_body);
    assert_eq!(destination_lambda.frame(), original_destination_frame);
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        original_destination_generation
    );
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        original_remembered_edges.as_slice()
    );
    assert_eq!(
        evaluator.thunk_resolve_card_table.dirty_cards(),
        original_dirty_cards.as_slice()
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_apply_root_storage_and_live_heap_fields_for_existing_destination() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    assert_eq!(plan.object_bodies(), 1);
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), gc_address(child));
    assert_eq!(request.destination(), destination_address);

    let application = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect("mixed reference writebacks apply to roots and live heap fields");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 4);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 5);
    assert_eq!(application.root_writebacks(), 3);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    assert_eq!(application.remembered_set_published_edges(), 1);
    assert_eq!(application.card_table_clear_report().dirty_cards(), 1);
    assert_eq!(application.card_table_dirty_cards_cleared(), 1);
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    evaluator
        .heap()
        .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda)
        .expect("existing destination body is bound");
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        HeapGeneration::Young
    );
    let expected_edges = [RememberedEdge::new(gc_address(parent), destination_address)];
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        expected_edges.as_slice()
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_validate_and_apply_live_heap_fields_with_primop_arguments() {
    {
        let (evaluator, child, parent, destination, poll, value_stack) =
            tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
        let destination_address = gc_address(destination);
        let primop_arguments = vec![child];
        let preflight = evaluator
            .validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
                poll,
                MinorGcPromotionPolicy::new(2),
                MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
                &value_stack,
                &primop_arguments,
            )
            .expect("mixed primop reference writebacks validate without mutation");

        assert_eq!(preflight.poll(), poll);
        assert_eq!(preflight.scanned_roots(), 5);
        assert_eq!(preflight.scanned_objects(), 2);
        assert_eq!(preflight.survivors(), 1);
        assert_eq!(preflight.reference_slots(), 6);
        assert_eq!(preflight.root_writebacks(), 4);
        assert_eq!(preflight.heap_field_writebacks(), 1);
        assert_eq!(preflight.object_bodies_preflighted(), 1);
        assert_eq!(preflight.object_generations_preflighted(), 1);
        assert_eq!(preflight.validated_root_writebacks(), 4);
        assert_eq!(preflight.live_heap_field_writebacks(), 1);
        assert_eq!(preflight.validated_live_writebacks(), 5);
        assert!(
            preflight
                .root_value_writeback_slots()
                .iter()
                .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
        );
        let relocated = relocated_value(ValueTag::Lambda, destination_address);
        for slot in preflight.root_value_writeback_slots() {
            assert_raw_eq(slot.value(), relocated);
        }
        assert_eq!(preflight.heap_field_writeback_slots().len(), 1);
        assert_eq!(
            resolved_heap_destination_address(preflight.heap_field_writeback_slots()[0].value()),
            Some(destination_address)
        );
        assert_raw_eq(value_stack[0], child);
        assert_raw_eq(primop_arguments[0], child);
        assert_raw_eq(
            evaluator
                .heap()
                .get_list(parent)
                .expect("parent list remains typed")
                .get(0)
                .expect("parent list element exists"),
            child,
        );
    }

    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let destination_address = gc_address(destination);
    let mut primop_arguments = vec![child];
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("mixed primop reference writebacks apply to roots and live heap fields");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 5);
    assert_eq!(application.scanned_objects(), 2);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 6);
    assert_eq!(application.root_writebacks(), 4);
    assert_eq!(application.heap_field_writebacks(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 5);
    assert_eq!(application.remembered_set_published_edges(), 1);
    assert_eq!(application.card_table_dirty_cards_cleared(), 1);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert_raw_eq(*value, relocated);
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(destination)
            .expect("destination remains heap-bound"),
        HeapGeneration::Young
    );
    let expected_edges = [RememberedEdge::new(gc_address(parent), destination_address)];
    assert_eq!(
        evaluator.thunk_resolve_remembered_set.edges(),
        expected_edges.as_slice()
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_reserved_destination_rejects_stale_worker_poll_before_reservation() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let stale_poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a worker collector poll");
    let sibling = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("sibling thunk allocation advances worker poll");
    let current_poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("sibling allocation requested a worker collector poll");
    let records_before = evaluator.heap().len();
    let worker_safepoints_before = evaluator.heap().allocation_safepoints();
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints();
    let value_stack = vec![child, sibling];

    let err = evaluator
        .validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            stale_poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect_err("stale worker poll rejects before destination reservation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll: stale_poll,
            current: Some(current_poll),
        },)
    );
    assert_eq!(evaluator.heap().len(), records_before);
    assert_eq!(
        evaluator.heap().allocation_safepoints(),
        worker_safepoints_before
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints(),
        permanent_safepoints_before
    );
}
