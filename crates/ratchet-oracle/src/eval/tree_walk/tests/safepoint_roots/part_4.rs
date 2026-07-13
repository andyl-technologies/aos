//! Split-out tests (part_4). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_forwarding_slots_reject_frame_borrow_without_forwarding_install() {
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
    let active_frame = evaluator.env[0].clone();
    let _held_frame_borrow = active_frame
        .borrow_slots_for_test()
        .expect("test holds active frame borrow");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
            &plan,
            &mut value_stack,
        )
        .expect_err("held frame borrow rejects before forwarding install");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Environment(EvalEnvError::BorrowConflict)
    );
    assert_eq!(
        evaluator
            .heap()
            .minor_gc_forwarding_value_at(source_address)
            .expect("forwarding source remains known"),
        None
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_reject_frame_borrow_before_body_or_field_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
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
    let active_frame = evaluator.env[0].clone();
    let _held_frame_borrow = active_frame
        .borrow_slots_for_test()
        .expect("test holds active frame borrow");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect_err("held frame borrow rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Environment(EvalEnvError::BorrowConflict)
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
fn reference_writebacks_reject_stale_source_remembered_set_before_live_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
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
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    let stale_edge = RememberedEdge::new(
        static_gc_address(0x3000_0000),
        static_gc_address(0x3000_1000),
    );
    evaluator
        .thunk_resolve_remembered_set
        .record(stale_edge)
        .expect("stale remembered edge records");
    let stale_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect_err("stale source remembered set rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::SourceRememberedSetLengthMismatch {
            expected: 1,
            actual: 2,
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
        stale_remembered_edges.as_slice()
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
fn reference_writebacks_reject_stale_source_card_table_before_live_mutation() {
    let (mut evaluator, child, parent, destination, poll, mut value_stack) =
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
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(destination_address, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives for existing destination");
    let extra_card_source = next_dirty_card_source(&evaluator.thunk_resolve_card_table);
    evaluator
        .thunk_resolve_card_table
        .mark_source(extra_card_source)
        .expect("stale card table source marks");
    let stale_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            &mut value_stack,
        )
        .expect_err("stale source card table rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::SourceCardTableLengthMismatch {
            expected: 1,
            actual: 2,
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
        stale_dirty_cards.as_slice()
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_validate_rejects_synthetic_destination_without_mutation() {
    let synthetic_destination = static_gc_address(0x1000_0000);
    let (evaluator, child, parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();

    let err = evaluator
        .validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(synthetic_destination, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect_err("synthetic destination rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: synthetic_destination,
            },
        )
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
fn reference_writebacks_reject_synthetic_destination_before_root_or_field_mutation() {
    let synthetic_destination = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let original_remembered_edges = evaluator.thunk_resolve_remembered_set.edges().to_vec();
    let original_dirty_cards = evaluator.thunk_resolve_card_table.dirty_cards().to_vec();

    let err = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(synthetic_destination, static_gc_address(0x2000_0000)),
            &mut value_stack,
        )
        .expect_err("synthetic destination rejects before live mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: synthetic_destination,
            },
        )
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
fn reference_writebacks_reject_stale_live_field_before_root_storage_mutation() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives");
    evaluator
        .heap
        .set_allocation_domain_for_test(child, HeapAllocationDomain::PermanentShared)
        .expect("test can stale the live field generation");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            &plan,
            &mut value_stack,
        )
        .expect_err("stale live field rejects before tree-walk root mutation");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                index: 4,
                expected: ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Young,
                },
                actual: ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Permanent,
                },
            },
        )
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
fn collector_poll_minor_gc_root_writebacks_reject_heap_field_partition_before_mutation() {
    let (mut evaluator, child, _parent, poll, mut value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();

    let err = evaluator
        .apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &mut value_stack,
        )
        .expect_err("root-only helper rejects mixed root/field writebacks");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::UnsupportedHeapFieldWritebacks {
            heap_field_writebacks: 1,
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
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn root_value_writebacks_preserve_reverse_depth_and_ready_import_indexes() {
    let (mut evaluator, mut value_stack) = tree_walk_with_indexed_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);

    assert_eq!(plan.len(), 22);

    let report = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect("indexed root writebacks apply");

    assert_eq!(report.writebacks(), plan.len());
    assert_raw_eq(
        value_stack[0],
        replacement_for_source(&plan, EvalRootSource::ValueStack { slot: 0 }),
    );
    assert_raw_eq(
        value_stack[1],
        replacement_for_source(&plan, EvalRootSource::ValueStack { slot: 1 }),
    );
    assert_raw_eq(
        evaluator.env[0].get(0).expect("outer frame slot exists"),
        replacement_for_source(&plan, EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }),
    );
    assert_raw_eq(
        evaluator.env[1].get(0).expect("inner frame slot exists"),
        replacement_for_source(&plan, EvalRootSource::TreeWalkFrame { frame: 1, slot: 0 }),
    );
    assert_raw_eq(
        evaluator.with_scopes[0].value(),
        replacement_for_source(&plan, EvalRootSource::WithScope { depth: 0 }),
    );
    assert_raw_eq(
        evaluator.with_scopes[1].value(),
        replacement_for_source(&plan, EvalRootSource::WithScope { depth: 1 }),
    );
    assert_raw_eq(
        evaluator.scoped_globals[0],
        replacement_for_source(&plan, EvalRootSource::ScopedGlobal { depth: 0 }),
    );
    assert_raw_eq(
        evaluator.scoped_globals[1],
        replacement_for_source(&plan, EvalRootSource::ScopedGlobal { depth: 1 }),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[1].env[0]
            .get(0)
            .expect("nearest suspended frame slot exists"),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedTreeWalkFrame {
                depth: 0,
                frame: 0,
                slot: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[0].env[0]
            .get(0)
            .expect("outer suspended frame slot exists"),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedTreeWalkFrame {
                depth: 1,
                frame: 0,
                slot: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[1].with_scopes[0].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedWithScope {
                depth: 0,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[0].with_scopes[0].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedWithScope {
                depth: 1,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[1].scoped_globals[0],
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedScopedGlobal {
                depth: 0,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.suspended_env_roots[0].scoped_globals[0],
        replacement_for_source(
            &plan,
            EvalRootSource::SuspendedScopedGlobal {
                depth: 1,
                scope_depth: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_force_roots[1],
        replacement_for_source(&plan, EvalRootSource::ForceContinuation { depth: 0 }),
    );
    assert_raw_eq(
        evaluator.active_force_roots[0],
        replacement_for_source(&plan, EvalRootSource::ForceContinuation { depth: 1 }),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[2].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 0,
                index: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[3].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 0,
                index: 1,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[0].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 1,
                index: 0,
            },
        ),
    );
    assert_raw_eq(
        evaluator.active_primop_arg_roots[1].value(),
        replacement_for_source(
            &plan,
            EvalRootSource::TreeWalkPrimopArgument {
                call_depth: 1,
                index: 1,
            },
        ),
    );
    let ImportCacheEntry::Ready {
        value: first_import,
        ..
    } = evaluator
        .import_cache
        .get(&PathBuf::from("/tmp/safepoint-root-writeback-01-ready.nix"))
        .expect("first ready import remains cached")
    else {
        panic!("first import cache entry remains ready");
    };
    assert_raw_eq(
        *first_import,
        replacement_for_source(&plan, EvalRootSource::ImportCache { index: 0 }),
    );
    let ImportCacheEntry::Ready {
        value: second_import,
        ..
    } = evaluator
        .import_cache
        .get(&PathBuf::from("/tmp/safepoint-root-writeback-03-ready.nix"))
        .expect("second ready import remains cached")
    else {
        panic!("second import cache entry remains ready");
    };
    assert_raw_eq(
        *second_import,
        replacement_for_source(&plan, EvalRootSource::ImportCache { index: 1 }),
    );
}

