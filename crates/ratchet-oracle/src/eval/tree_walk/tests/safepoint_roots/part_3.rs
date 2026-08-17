//! Split-out tests (part_3). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_apply_reserved_worker_poll_switch_and_promote_destination() {
    let ir = lower("let keep = 1; in x: keep");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a worker collector poll");
    assert_eq!(poll.tier(), RuntimeAllocatorTier::TierAOneShot);
    let records_before = evaluator.heap().len();
    let mut value_stack = vec![child];

    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(0),
            &mut value_stack,
        )
        .expect("reserved worker-poll writebacks apply");

    assert_ne!(application.poll(), poll);
    assert_eq!(
        application.poll().tier(),
        RuntimeAllocatorTier::TierAOneShot
    );
    assert_eq!(
        evaluator
            .heap()
            .allocation_safepoints()
            .last_safepoint_collector_poll(),
        Some(application.poll())
    );
    assert_eq!(evaluator.heap().len(), records_before + 1);
    assert_eq!(application.scanned_roots(), 1);
    assert_eq!(application.scanned_objects(), 1);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 1);
    assert_eq!(application.root_writebacks(), 1);
    assert_eq!(application.heap_field_writebacks(), 0);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 1);
    assert_eq!(application.live_heap_field_writebacks(), 0);
    assert_eq!(application.applied_live_writebacks(), 1);
    assert_eq!(application.remembered_set_published_edges(), 0);
    assert_eq!(application.card_table_dirty_cards_cleared(), 0);
    assert_ne!(gc_address(value_stack[0]), gc_address(child));
    assert_eq!(
        evaluator
            .heap()
            .generation(value_stack[0])
            .expect("promoted reserved destination is heap-bound"),
        HeapGeneration::Old
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_reserved_destination_plan_reports_promoted_placement_bytes() {
    let ir = lower("let keep = 1; in x: keep");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda child evaluates");
    let child_address = gc_address(child);
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a worker collector poll");
    let records_before = evaluator.heap().len();
    let value_stack = vec![child];

    let plan = evaluator
        .collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(0),
            &value_stack,
        )
        .expect("reserved promoted destination reference writeback plan derives");

    assert_ne!(plan.poll(), poll);
    assert_eq!(evaluator.heap().len(), records_before + 1);
    assert_eq!(plan.scanned_roots(), 1);
    assert_eq!(plan.scanned_objects(), 1);
    assert_eq!(plan.survivors(), 1);
    assert_eq!(plan.reference_slots(), 1);
    assert_eq!(plan.destination_placements(), 1);
    assert_eq!(
        plan.placement_plan().placements()[0].source(),
        child_address
    );
    assert_eq!(
        plan.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Old
    );
    assert_eq!(plan.nursery_reserved_bytes(), 0);
    assert_eq!(
        plan.old_reserved_bytes(),
        plan.object_body_plan().requests()[0].size_bytes()
    );
    assert_eq!(plan.total_reserved_bytes(), plan.old_reserved_bytes());
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), child_address);
    assert_eq!(request.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(request.destination_generation(), HeapGeneration::Old);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_reserved_destination_apply_accepts_periodic_poll_without_reservation_poll()
{
    let (mut evaluator, poll, mut value_stack) =
        tree_walk_with_periodic_poll_before_single_young_reservation();
    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("reserved bridge applies when reservation itself does not poll");

    assert_periodic_poll_reserved_application_without_reservation_poll(
        &evaluator,
        value_stack[0],
        application.applied_root_writebacks(),
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_reserved_forwarding_apply_accepts_periodic_poll_without_reservation_poll() {
    let (mut evaluator, poll, mut value_stack) =
        tree_walk_with_periodic_poll_before_single_young_reservation();
    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("reserved bridge applies when reservation itself does not poll");

    assert_periodic_poll_reserved_application_without_reservation_poll(
        &evaluator,
        value_stack[0],
        application.applied_root_writebacks(),
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_validate_reserved_destination_without_live_mutation() {
    let (mut evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let child_address = gc_address(child);
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let preflight = evaluator
        .validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect("reserved destination reference writebacks validate without live mutation");

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
    let destination_address = gc_address(preflight.root_value_writeback_slots()[0].value());
    assert_ne!(destination_address, child_address);
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
    assert_eq!(
        evaluator
            .heap()
            .generation(relocated)
            .expect("reserved destination is heap-bound"),
        HeapGeneration::Young
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
fn reference_writebacks_reserved_destination_plan_uses_unbound_placeholder_body() {
    let (mut evaluator, child, _parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let child_address = gc_address(child);
    let plan = evaluator
        .collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect("reserved destination reference writeback plan derives");

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
    assert_eq!(plan.object_bodies(), 1);
    let request = plan.object_body_plan().requests()[0];
    assert_eq!(request.source(), child_address);
    assert_ne!(request.destination(), child_address);
    assert_eq!(request.action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(request.destination_generation(), HeapGeneration::Young);
    assert!(matches!(
        evaluator
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let preflight = evaluator
        .validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            &plan,
            &value_stack,
        )
        .expect("reserved destination plan preflights");
    assert_eq!(preflight.object_bodies_preflighted(), 1);
    assert!(matches!(
        evaluator
            .heap()
            .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
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
fn reference_writebacks_apply_reserved_destination_with_primop_arguments() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let child_address = gc_address(child);
    let mut primop_arguments = vec![child];
    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("reserved destination writebacks apply to roots and live heap fields");

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
    assert_eq!(application.card_table_clear_report().dirty_cards(), 1);
    assert_eq!(application.card_table_dirty_cards_cleared(), 1);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let destination_address = gc_address(application.root_value_writeback_slots()[0].value());
    assert_ne!(destination_address, child_address);
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
    assert_raw_eq(primop_arguments[0], relocated);
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
            .generation(relocated)
            .expect("reserved destination remains heap-bound"),
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
fn reference_writebacks_apply_reserved_destination_with_forwarding_slots() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);
    let plan = evaluator
        .collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            &value_stack,
        )
        .expect("reserved destination reference writeback plan derives");
    assert_eq!(plan.forwarding_pointers(), 1);
    let forwarding_slot = plan.forwarding_slots()[0];
    assert_eq!(forwarding_slot.source(), source_address);
    let forwarded = forwarding_slot
        .forwarded_value()
        .expect("forwarding slot is filled");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    assert_ne!(destination_address, source_address);

    let application = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            &plan,
            &mut value_stack,
        )
        .expect("reserved destination writebacks install forwarding and apply");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    assert_eq!(
        evaluator
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("forwarding source remains known"),
        Some(forwarded)
    );
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
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
fn reference_writebacks_apply_reserved_destination_wrapper_with_forwarding_slots() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);

    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("reserved destination wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.object_bodies_written(), 1);
    assert_eq!(application.object_generations_written(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
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
fn reference_writebacks_apply_reserved_forwarding_wrapper_with_primop_arguments() {
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);
    let mut primop_arguments = vec![child];

    let application = evaluator
        .apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("reserved destination primop wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.root_value_writeback_slots().len(), 4);
    assert_eq!(application.heap_field_writeback_slots().len(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 5);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
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
fn reference_writebacks_apply_current_reserved_forwarding_wrapper() {
    let (mut evaluator, child, parent, _poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);

    let application = evaluator
        .apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            RuntimeAllocatorTier::PermanentShared,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect("current reserved destination wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.applied_root_writebacks(), 3);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 4);
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
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
fn reference_writebacks_apply_current_reserved_forwarding_wrapper_with_primop_arguments() {
    let (mut evaluator, child, parent, _poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let source_address = gc_address(child);
    let mut primop_arguments = vec![child];

    let application = evaluator
        .apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            RuntimeAllocatorTier::PermanentShared,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("current reserved destination primop wrapper installs forwarding and applies");

    assert_eq!(application.forwarding_pointers_installed(), 1);
    assert_eq!(application.root_value_writeback_slots().len(), 4);
    assert_eq!(application.heap_field_writeback_slots().len(), 1);
    assert_eq!(application.applied_root_writebacks(), 4);
    assert_eq!(application.live_heap_field_writebacks(), 1);
    assert_eq!(application.applied_live_writebacks(), 5);
    let forwarded = evaluator
        .heap()
        .minor_gc_forwarding_value_at(source_address)
        .expect("forwarding source remains known")
        .expect("forwarding slot installs");
    let destination_address =
        resolved_heap_destination_address(forwarded).expect("forwarded value is heap-backed");
    let relocated = relocated_value(ValueTag::Lambda, destination_address);
    assert_raw_eq(value_stack[0], relocated);
    assert_raw_eq(primop_arguments[0], relocated);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        relocated,
    );
    assert_raw_eq(
        evaluator
            .heap()
            .get_list(parent)
            .expect("parent list remains typed")
            .get(0)
            .expect("parent list element exists"),
        relocated,
    );
    assert!(evaluator.thunk_resolve_card_table.dirty_cards().is_empty());
}

#[test]
fn reference_writebacks_current_reserved_forwarding_wrapper_rejects_missing_poll_without_reservation()
 {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::disabled()),
    );
    let records_before = evaluator.heap().len();
    let mut value_stack = Vec::new();

    let err = evaluator
        .apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            RuntimeAllocatorTier::TierAOneShot,
            MinorGcPromotionPolicy::new(2),
            &mut value_stack,
        )
        .expect_err("missing current poll rejects before reservation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(
            TreeWalkSafepointScanError::NoCurrentCollectorPoll {
                tier: RuntimeAllocatorTier::TierAOneShot
            },
        )
    );
    assert_eq!(evaluator.heap().len(), records_before);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_forwarding_slots_reject_occupied_before_live_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks_existing_destination();
    let source_address = gc_address(child);
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
    let forwarding_slot = plan.forwarding_slots()[0];
    let forwarded = forwarding_slot
        .forwarded_value()
        .expect("forwarding slot is filled");
    evaluator
        .heap
        .install_collector_poll_minor_gc_forwarding_slots(plan.forwarding_slots())
        .expect("initial forwarding slot installs");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            &plan,
            &mut value_stack,
        )
        .expect_err("occupied forwarding slot rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
                index: 0,
                address: source_address,
                actual: forwarded,
            },
        ))
    );
    assert_raw_eq(value_stack[0], child);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        child,
    );
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
