//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn safepoint_roots_include_active_tree_walk_state_and_interned_roots() {
    let ir = lower("null");
    let mut evaluator = TreeWalk::new(&ir);
    let live = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"live-root".to_vec()))
        .expect("string allocates");

    let frame = EvalFrame::new(3).expect("frame allocates");
    frame.set(1, live).expect("frame slot sets");
    evaluator.env.push(frame);
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, ir.root, live));
    evaluator.scoped_globals.push(live);
    evaluator
        .push_active_force_root(ir.root, Span::new(0, 0), live)
        .expect("force root pushes");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            Span::new(0, 0),
            &[EvalPrimOpArg::new(ir.root, Span::new(0, 0), live)],
        )
        .expect("primop roots push");
    let suspended_frame = EvalFrame::new(2).expect("suspended frame allocates");
    suspended_frame
        .set(0, live)
        .expect("suspended frame slot sets");
    evaluator
        .reserve_suspended_env_root_frame(ir.root, Span::new(0, 0))
        .expect("suspended env root reserves");
    evaluator.push_suspended_env_roots(
        vec![suspended_frame],
        vec![EvalWithScope::new(EvalModuleId::ROOT, ir.root, live)],
        vec![live],
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-import.nix"),
        ImportCacheEntry::Ready {
            value: live,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );

    let roots = evaluator
        .safepoint_root_set()
        .expect("safepoint roots build");
    let sources: Vec<_> = roots.roots().iter().map(EvalRoot::source).collect();

    assert!(sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 1 }));
    assert!(sources.contains(&&EvalRootSource::WithScope { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ScopedGlobal { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ForceContinuation { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::TreeWalkPrimopArgument {
        call_depth: 0,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedTreeWalkFrame {
        depth: 0,
        frame: 0,
        slot: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedWithScope {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedScopedGlobal {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 0,
    }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 2 }));

    let scan = evaluator
        .safepoint_heap_scan()
        .expect("safepoint heap scans");
    assert!(scan.roots().iter().any(|root| root.value().raw_eq(live)));
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(live))
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn root_value_writebacks_update_supported_tree_walk_roots() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let sources: Vec<_> = plan
        .writebacks()
        .iter()
        .map(|write| write.source())
        .collect();

    assert_eq!(plan.len(), 10);
    assert!(sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(sources.contains(&&EvalRootSource::WithScope { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ScopedGlobal { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ForceContinuation { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::TreeWalkPrimopArgument {
        call_depth: 0,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedTreeWalkFrame {
        depth: 0,
        frame: 0,
        slot: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedWithScope {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedScopedGlobal {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(sources.contains(&&EvalRootSource::ValueStack { slot: 0 }));
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);

    let report = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect("supported root writebacks apply to tree-walk roots");

    assert_eq!(report.writebacks(), plan.len());
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        relocated_value(ValueTag::Lambda, nursery_base),
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn root_value_writebacks_update_caller_owned_primop_arguments() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let mut primop_arguments = vec![live];
    let nursery_base = static_gc_address(0x1000_0000);
    let plan = root_writeback_plan_for_supported_mutable_roots_with_primop_arguments(
        &evaluator,
        &value_stack,
        &primop_arguments,
        nursery_base,
    );
    let sources: Vec<_> = plan
        .writebacks()
        .iter()
        .map(|write| write.source())
        .collect();

    assert_eq!(plan.len(), 11);
    assert!(sources.contains(&&EvalRootSource::PrimopArgument { index: 0 }));

    let report = evaluator
        .apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            &plan,
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("root and primop-argument writebacks apply");

    assert_eq!(report.writebacks(), plan.len());
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        replacement_for_source(&plan, EvalRootSource::ValueStack { slot: 0 }),
    );
    assert_raw_eq(
        primop_arguments[0],
        replacement_for_source(&plan, EvalRootSource::PrimopArgument { index: 0 }),
    );
    assert!(!primop_arguments[0].raw_eq(live));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn root_value_writebacks_reject_late_frame_borrow_before_partial_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let suspended_frame = evaluator.suspended_env_roots[0].env[0].clone();
    let _held_frame_borrow = suspended_frame
        .borrow_slots_for_test()
        .expect("test holds suspended frame borrow");

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
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
fn collector_poll_minor_gc_root_writebacks_apply_to_safepoint_roots() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let report = evaluator
        .apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
        )
        .expect("collector-poll root writebacks apply");

    assert_eq!(report.poll(), poll);
    assert_eq!(report.scanned_roots(), 10);
    assert_eq!(report.scanned_objects(), 1);
    assert_eq!(report.survivors(), 1);
    assert_eq!(report.reference_slots(), 10);
    assert_eq!(report.root_writebacks(), 10);
    assert_eq!(report.heap_field_writebacks(), 0);
    assert_eq!(report.applied_root_writebacks(), 10);
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        relocated_value(ValueTag::Lambda, nursery_base),
    );
    assert!(!value_stack[0].raw_eq(live));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_root_writebacks_apply_to_primop_argument_roots() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let mut primop_arguments = vec![live];
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let report = evaluator
        .apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect("collector-poll primop root writebacks apply");

    assert_eq!(report.poll(), poll);
    assert_eq!(report.scanned_roots(), 11);
    assert_eq!(report.scanned_objects(), 1);
    assert_eq!(report.survivors(), 1);
    assert_eq!(report.reference_slots(), 11);
    assert_eq!(report.root_writebacks(), 11);
    assert_eq!(report.heap_field_writebacks(), 0);
    assert_eq!(report.applied_root_writebacks(), 11);
    assert_supported_mutable_roots_eq(
        &evaluator,
        &value_stack,
        relocated_value(ValueTag::Lambda, nursery_base),
    );
    assert_raw_eq(
        primop_arguments[0],
        relocated_value(ValueTag::Lambda, nursery_base),
    );
    assert!(!primop_arguments[0].raw_eq(live));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_root_writebacks_reject_stale_poll_before_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let later = alloc_test_lambda(&mut evaluator, 99);
    assert!(!later.raw_eq(live));
    let current = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("later allocation requested a collector poll");

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
        .expect_err("stale poll is rejected");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        },)
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
fn collector_poll_minor_gc_reference_writeback_plan_rejects_stale_poll_before_mutation() {
    let (mut evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let later = alloc_test_lambda(&mut evaluator, 100);
    assert!(!later.raw_eq(live));
    let current = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("later allocation requested a collector poll");

    let err = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &value_stack,
        )
        .expect_err("stale poll is rejected");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        },)
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
fn collector_poll_minor_gc_reference_writebacks_apply_to_safepoint_buffers_all_roots() {
    let (evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("collector-poll reference writebacks apply to buffers");

    assert_eq!(application.poll(), poll);
    assert_eq!(application.scanned_roots(), 10);
    assert_eq!(application.scanned_objects(), 1);
    assert_eq!(application.survivors(), 1);
    assert_eq!(application.reference_slots(), 10);
    assert_eq!(application.root_writebacks(), 10);
    assert_eq!(application.heap_field_writebacks(), 0);
    assert_eq!(application.applied_root_writebacks(), 10);
    assert_eq!(application.applied_heap_field_writebacks(), 0);
    assert_eq!(application.applied_writebacks(), 10);
    assert_eq!(application.report().root_writebacks(), 10);
    assert_eq!(application.root_value_writeback_slots().len(), 10);
    assert!(application.heap_field_writeback_slots().is_empty());
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writeback_plan_and_buffers_include_caller_owned_primop_arguments() {
    let (evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let primop_arguments = vec![live];
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let nursery_base = static_gc_address(0x1000_0000);
    let bases = MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000));
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            bases,
            &value_stack,
            &primop_arguments,
        )
        .expect("collector-poll reference writeback plan includes primop arguments");

    assert_eq!(plan.scanned_roots(), 11);
    assert_eq!(plan.scanned_objects(), 1);
    assert_eq!(plan.survivors(), 1);
    assert_eq!(plan.reference_slots(), 11);
    assert_eq!(plan.root_writebacks(), 11);
    assert_eq!(plan.heap_field_writebacks(), 0);
    let root_sources: Vec<_> = plan
        .writebacks()
        .root_writebacks()
        .writebacks()
        .iter()
        .map(|writeback| writeback.source())
        .collect();
    assert!(root_sources.contains(&&EvalRootSource::PrimopArgument { index: 0 }));

    let application = evaluator
        .apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            &plan,
            &value_stack,
            &primop_arguments,
        )
        .expect("reference writebacks apply to primop argument buffers");
    let derived_application = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            poll,
            MinorGcPromotionPolicy::new(2),
            bases,
            &value_stack,
            &primop_arguments,
        )
        .expect("poll-derived reference writebacks apply to primop argument buffers");

    assert_eq!(application, derived_application);
    assert_eq!(application.applied_root_writebacks(), 11);
    assert_eq!(application.applied_heap_field_writebacks(), 0);
    assert_eq!(application.root_value_writeback_slots().len(), 11);
    assert!(
        application
            .root_value_writeback_slots()
            .iter()
            .any(|slot| slot.source() == &EvalRootSource::PrimopArgument { index: 0 })
    );
    let relocated = relocated_value(ValueTag::Lambda, nursery_base);
    for slot in application.root_value_writeback_slots() {
        assert_raw_eq(slot.value(), relocated);
    }
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
    assert_raw_eq(primop_arguments[0], live);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_reference_writebacks_reject_stale_poll_before_buffers() {
    let (mut evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let later = alloc_test_lambda(&mut evaluator, 101);
    assert!(!later.raw_eq(live));
    let current = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("later allocation requested a collector poll");

    let err = evaluator
        .apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &value_stack,
        )
        .expect_err("stale poll is rejected before buffer application");

    assert_eq!(
        err,
        TreeWalkSafepointRootWritebackError::Scan(TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        },)
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
fn reference_writebacks_to_safepoint_buffers_reject_stale_root_slot() {
    let (evaluator, live, value_stack) = tree_walk_with_supported_mutable_roots();
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
            &value_stack,
        )
        .expect("reference writeback plan derives");
    let stale = Value::int(99);
    evaluator.env[0]
        .set(0, stale)
        .expect("active frame slot can be made stale");

    let err = evaluator
        .apply_reference_writebacks_to_safepoint_buffers(&plan, &value_stack)
        .expect_err("stale typed root slot rejects buffer application");

    let TreeWalkSafepointRootWritebackError::Heap(
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch { actual_tag, .. },
    ) = err
    else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(actual_tag, ValueTag::Int);
    assert_raw_eq(value_stack[0], live);
    assert_raw_eq(
        evaluator.env[0].get(0).expect("active frame slot exists"),
        stale,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn typed_reference_writeback_plan_rejects_stale_heap_field_before_root_buffer_mutation() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (evaluator, child, _parent, poll, value_stack) =
        tree_walk_with_mixed_root_and_heap_field_writebacks();
    let plan = evaluator
        .collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
            &value_stack,
        )
        .expect("mixed reference writeback plan derives");
    let root_plan = plan.writebacks().root_writebacks();
    let heap_plan = plan.writebacks().heap_field_writebacks();
    let mut root_slots: Vec<_> = root_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollRootValueWritebackSlot::new(
                writeback.source().clone(),
                writeback
                    .expected_value()
                    .expect("expected root reconstructs"),
            )
        })
        .collect();
    let mut heap_slots: Vec<_> = heap_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollHeapFieldWritebackSlot::new(
                writeback.validation_object(),
                writeback.writeback_object(),
                writeback.field_index(),
                writeback.source().clone(),
                ResolvedValueGeneration::Inline,
            )
        })
        .collect();

    let err = plan
        .writebacks()
        .apply_to_value_and_heap_field_slots(&mut root_slots, &mut heap_slots)
        .expect_err("stale heap-field metadata rejects typed combined application");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 4,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    for slot in &root_slots {
        assert_raw_eq(slot.value(), child);
    }
    assert_eq!(heap_slots[0].value(), ResolvedValueGeneration::Inline);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn reference_writebacks_to_safepoint_buffers_reject_stale_live_heap_field() {
    let nursery_base = static_gc_address(0x1000_0000);
    let (mut evaluator, child, parent, poll, value_stack) =
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
        .apply_reference_writebacks_to_safepoint_buffers(&plan, &value_stack)
        .expect_err("stale live heap-field slot rejects buffer application");

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

