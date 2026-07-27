//! Split-out tests (part_5). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn root_value_writebacks_reject_stale_value_stack_before_tree_walk_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let stale_value = Value::int(1);
    value_stack[0] = stale_value;

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect_err("stale value-stack root rejects before live tree-walk roots mutate");

    assert!(matches!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                actual_tag: ValueTag::Int,
                ..
            }
        )
    ));
    assert!(value_stack[0].raw_eq(stale_value));
    assert_supported_tree_walk_roots_eq(&evaluator, live);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn root_value_writebacks_reject_stale_primop_argument_before_tree_walk_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let mut primop_arguments = vec![live];
    let nursery_base = static_gc_address(0x1000_0000);
    let plan = root_writeback_plan_for_supported_mutable_roots_with_primop_arguments(
        &evaluator,
        &value_stack,
        &primop_arguments,
        nursery_base,
    );
    let stale_value = Value::int(1);
    primop_arguments[0] = stale_value;

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            &plan,
            &mut value_stack,
            &mut primop_arguments,
        )
        .expect_err("stale primop argument rejects before tree-walk roots mutate");

    assert!(matches!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                actual_tag: ValueTag::Int,
                ..
            }
        )
    ));
    assert!(primop_arguments[0].raw_eq(stale_value));
    assert_supported_mutable_roots_eq(&evaluator, &value_stack, live);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn root_value_writebacks_reject_stale_active_frame_before_any_mutation() {
    let (mut evaluator, live, mut value_stack) = tree_walk_with_supported_mutable_roots();
    let nursery_base = static_gc_address(0x1000_0000);
    let plan =
        root_writeback_plan_for_supported_mutable_roots(&evaluator, &value_stack, nursery_base);
    let stale_value = Value::int(1);
    evaluator.env[0]
        .set(0, stale_value)
        .expect("test can stale active frame slot");

    let err = evaluator
        .apply_root_value_writebacks_to_safepoint_roots(&plan, &mut value_stack)
        .expect_err("stale active frame rejects before root mutation");

    assert!(matches!(
        err,
        TreeWalkSafepointRootWritebackError::Heap(
            EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                actual_tag: ValueTag::Int,
                ..
            }
        )
    ));
    assert!(value_stack[0].raw_eq(live));
    assert!(
        evaluator.env[0]
            .get(0)
            .expect("active frame slot remains readable")
            .raw_eq(stale_value)
    );
    assert!(evaluator.with_scopes[0].value().raw_eq(live));
    assert!(evaluator.scoped_globals[0].raw_eq(live));
    assert!(evaluator.active_force_roots[0].raw_eq(live));
    assert!(evaluator.active_primop_arg_roots[0].value().raw_eq(live));
    assert!(
        evaluator.suspended_env_roots[0].env[0]
            .get(0)
            .expect("suspended frame slot remains readable")
            .raw_eq(live)
    );
    assert!(
        evaluator.suspended_env_roots[0].with_scopes[0]
            .value()
            .raw_eq(live)
    );
    assert!(evaluator.suspended_env_roots[0].scoped_globals[0].raw_eq(live));
    let ImportCacheEntry::Ready { value, .. } = evaluator
        .import_cache
        .values()
        .next()
        .expect("ready import cache entry exists")
    else {
        panic!("import cache entry remains ready");
    };
    assert!(value.raw_eq(live));
}

#[test]
fn active_safepoint_roots_are_removed_after_force_and_primop_errors() {
    let recursive = lower("let x = x; in x");
    let mut recursive_eval = TreeWalk::new(&recursive);
    recursive_eval
        .eval_root()
        .expect_err("recursive force reports blackhole");
    let recursive_roots = recursive_eval
        .safepoint_root_set()
        .expect("roots build after force error");
    assert!(recursive_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));

    let bad_primop = lower("let add = builtins.add; in add 1 \"x\"");
    let mut primop_eval = TreeWalk::new(&bad_primop);
    primop_eval
        .eval_root()
        .expect_err("bad first-class primop reports type error");
    let primop_roots = primop_eval
        .safepoint_root_set()
        .expect("roots build after primop error");
    assert!(primop_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::TreeWalkPrimopArgument { .. }
                | EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_poll_scan_uses_tree_walk_roots_plus_transient_value_stack() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let root = evaluator.eval_root().expect("lambda evaluates");
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");

    assert_eq!(
        poll.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );

    let remembered_set = RememberedSet::new();
    let empty_scan = evaluator
        .safepoint_collector_poll_scan(poll, [])
        .expect("collector poll scan accepts empty transient roots");
    assert!(empty_scan.scan().roots().is_empty());
    let empty_minor_gc = evaluator
        .heap()
        .plan_collector_poll_minor_gc(
            &empty_scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("empty collector poll scan plans");
    assert!(empty_minor_gc.plan().survivors().is_empty());

    let scan = evaluator
        .safepoint_collector_poll_scan(poll, [root])
        .expect("collector poll roots scan");
    let stack_root = scan
        .scan()
        .roots()
        .iter()
        .find(|scan_root| scan_root.source() == &EvalRootSource::ValueStack { slot: 0 })
        .expect("transient value-stack root records");
    assert!(stack_root.value().raw_eq(root));
    assert!(
        scan.scan()
            .objects()
            .iter()
            .any(|object| { object.value().raw_eq(root) })
    );

    let minor_gc = evaluator
        .heap()
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("collector poll minor-GC planning accepts the tree-walk scan");
    assert_eq!(minor_gc.plan().survivors().len(), 1);
    assert_eq!(minor_gc.plan().survivors()[0].address(), gc_address(root));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_allocation_safepoint_rewrites_registered_transient_value_stack_root() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let local_source = evaluator
        .heap
        .alloc_lambda(test_lambda_record())
        .expect("registered local lambda allocates");
    let local_source_address = gc_address(local_source);
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let allocated: Value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_tree_walk_thunk(ir.root, span, EvalThunk::new(ir.root))
        })
        .expect("GC-stress allocation rewrites registered transient roots");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert_ne!(gc_address(roots[0]), local_source_address);
    assert_eq!(roots[0].tag(), ValueTag::Lambda);
    assert_eq!(allocated.tag(), ValueTag::Thunk);
    assert!(!allocated.raw_eq(roots[0]));
    assert!(has_forwarding_destination(evaluator.heap(), roots[0]));
    assert!(has_forwarding_destination(evaluator.heap(), allocated));
    assert_eq!(
        evaluator
            .heap()
            .generation(roots[0])
            .expect("registered root destination remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(allocated)
            .expect("allocated value destination remains heap-bound"),
        HeapGeneration::Young
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_allocation_safepoint_rewrites_deep_force_visited_roots() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let local_source = evaluator
        .heap
        .alloc_lambda(test_lambda_record())
        .expect("registered local lambda allocates");
    let local_source_address = gc_address(local_source);
    let mut visited = vec![local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let allocated: Value = evaluator
        .with_deep_force_visited_roots(ir.root, span, &mut visited, |eval, _visited| {
            eval.alloc_tree_walk_thunk(ir.root, span, EvalThunk::new(ir.root))
        })
        .expect("GC-stress allocation rewrites deep-force visited roots");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert_ne!(gc_address(visited[0]), local_source_address);
    assert_eq!(visited[0].tag(), ValueTag::Lambda);
    assert_eq!(allocated.tag(), ValueTag::Thunk);
    assert!(!allocated.raw_eq(visited[0]));
    assert!(has_forwarding_destination(evaluator.heap(), visited[0]));
    assert!(has_forwarding_destination(evaluator.heap(), allocated));
    assert_eq!(
        evaluator
            .heap()
            .generation(visited[0])
            .expect("registered visited root destination remains heap-bound"),
        HeapGeneration::Young
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(allocated)
            .expect("allocated value destination remains heap-bound"),
        HeapGeneration::Young
    );
}

#[test]
fn transient_value_stack_roots_restore_after_body_error() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let original = Value::int(7);
    let mut roots = [original];
    let bad_id = IrId::new(999);

    let error = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            assert_eq!(eval.transient_value_stack_roots().len(), 1);
            assert!(eval.transient_value_stack_roots()[0].raw_eq(original));
            Err::<(), TreeWalkError>(TreeWalkError::new(
                TreeWalkErrorKind::InvalidNodeId { id: bad_id },
                span,
            ))
        })
        .expect_err("body error propagates");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidNodeId { id } if id == bad_id
    ));
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(roots[0].raw_eq(original));
}

#[test]
fn transient_value_stack_roots_restore_after_body_panic() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let span = Span::new(0, 0);
    let original = Value::int(9);
    let mut roots = [original];

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), TreeWalkError> =
            evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
                assert_eq!(eval.transient_value_stack_roots().len(), 1);
                assert!(eval.transient_value_stack_roots()[0].raw_eq(original));
                assert!(eval.set_current_transient_value_stack_root(0, Value::int(10)));
                panic!("transient root cleanup test panic");
            });
    }));

    assert!(panic.is_err());
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(roots[0].raw_eq(Value::int(10)));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn owned_eval_records_gc_stress_boundary_worker_scan() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");

    let scans = outcome.gc_stress_boundary_scans();
    assert_eq!(scans.len(), 1);
    assert!(scans.permanent_shared().is_none());
    let worker_scan = scans.worker().expect("worker boundary scan records");
    assert_eq!(
        worker_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        worker_scan.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert!(scan_has_value_stack_root(worker_scan, outcome.value()));
    assert!(scan_has_object(worker_scan, outcome.value()));
}

#[test]
fn owned_eval_records_gc_stress_boundary_permanent_scan() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let scans = outcome.gc_stress_boundary_scans();
    assert_eq!(scans.len(), 1);
    assert!(scans.worker().is_none());
    let permanent_scan = scans
        .permanent_shared()
        .expect("permanent boundary scan records");
    assert_eq!(
        permanent_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_scan.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert!(scan_has_value_stack_root(permanent_scan, outcome.value()));
    assert!(scan_has_object(permanent_scan, outcome.value()));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn attr_path_eval_records_gc_stress_boundary_scan() {
    let ir = lower("{ f = x: x; }");
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"f".to_vec()],
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
        None,
    )
    .expect("attr-path selection evaluates under GC stress");

    let worker_scan = outcome
        .gc_stress_boundary_scans()
        .worker()
        .expect("selected lambda boundary scan records");
    assert_eq!(
        worker_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert!(scan_has_value_stack_root(worker_scan, outcome.value()));
    assert!(scan_has_object(worker_scan, outcome.value()));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn owned_eval_plans_gc_stress_boundary_worker_minor_gc() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("boundary scan plans as minor GC");

    assert_eq!(plans.len(), 1);
    assert!(plans.permanent_shared().is_none());
    let worker_plan = plans.worker().expect("worker boundary plan records");
    assert_eq!(
        worker_plan.roots(),
        &[ResolvedValueGeneration::young(gc_address(outcome.value()))]
    );
    assert_eq!(worker_plan.plan().survivors().len(), 1);
    assert_eq!(
        worker_plan.plan().survivors()[0].address(),
        gc_address(outcome.value())
    );
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_minor_gc() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("boundary scan plans as minor GC");

    assert_eq!(plans.len(), 1);
    assert!(plans.worker().is_none());
    let permanent_plan = plans
        .permanent_shared()
        .expect("permanent boundary plan records");
    let permanent_root = ResolvedValueGeneration::permanent(gc_address(outcome.value()));
    assert_eq!(permanent_plan.roots().len(), 2);
    assert!(
        permanent_plan
            .roots()
            .iter()
            .all(|root| *root == permanent_root)
    );
    assert!(permanent_plan.plan().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn owned_eval_plans_gc_stress_boundary_worker_relocation_destinations() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);
    let old_base = static_gc_address(0x2000_0000);

    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect("boundary scan plans relocation destinations");

    assert_eq!(destinations.len(), 1);
    assert!(destinations.permanent_shared().is_none());
    let worker_destinations = destinations
        .worker()
        .expect("worker relocation destinations record");
    assert_eq!(worker_destinations.destinations().len(), 1);
    assert_eq!(
        worker_destinations.destinations()[0].source(),
        gc_address(outcome.value())
    );
    assert_eq!(
        worker_destinations.destinations()[0].destination(),
        nursery_base
    );
    assert_eq!(
        worker_destinations.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert!(worker_destinations.allocation_plan().nursery_bytes() > 0);
    assert_eq!(worker_destinations.allocation_plan().old_bytes(), 0);
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_relocation_destinations() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan plans relocation destinations");

    assert_eq!(destinations.len(), 1);
    assert!(destinations.worker().is_none());
    let permanent_destinations = destinations
        .permanent_shared()
        .expect("permanent relocation report records");
    assert!(permanent_destinations.destinations().is_empty());
    assert_eq!(permanent_destinations.allocation_plan().nursery_bytes(), 0);
    assert_eq!(permanent_destinations.allocation_plan().old_bytes(), 0);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn owned_eval_plans_gc_stress_boundary_worker_commit_metadata() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("boundary scan builds paired relocation plan");

    assert_eq!(plans.len(), 1);
    assert!(plans.permanent_shared().is_none());
    let worker_plan = plans.worker().expect("worker paired plan records");
    assert_eq!(worker_plan.minor_gc_plan().plan().survivors().len(), 1);
    assert_eq!(
        worker_plan.relocation_destinations().destinations()[0].destination(),
        nursery_base
    );
    let commit = worker_plan
        .commit_plan()
        .expect("paired boundary plan builds commit metadata");
    assert_eq!(
        commit.reference_slots(),
        worker_plan.minor_gc_plan().reference_slots()
    );
    assert_eq!(commit.commit_plan().object_copies().copies().len(), 1);
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].destination(),
        nursery_base
    );
    assert_eq!(
        commit.commit_plan().forwarding_pointers().pointers().len(),
        1
    );
    assert_eq!(
        commit.reference_slots()[0].value_tag(),
        Some(ValueTag::Lambda)
    );
    let root_writebacks = commit
        .root_writeback_plan()
        .expect("root writeback metadata builds");
    assert_eq!(root_writebacks.len(), 1);
    assert_eq!(
        root_writebacks.writebacks()[0].expected_tag(),
        ValueTag::Lambda
    );
    assert_eq!(
        root_writebacks.writebacks()[0].replacement_tag(),
        ValueTag::Lambda
    );
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_commit_metadata() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan builds paired relocation plan");

    assert_eq!(plans.len(), 1);
    assert!(plans.worker().is_none());
    let permanent_plan = plans
        .permanent_shared()
        .expect("permanent paired plan records");
    assert!(permanent_plan.minor_gc_plan().plan().is_empty());
    assert!(
        permanent_plan
            .relocation_destinations()
            .destinations()
            .is_empty()
    );
    let commit = permanent_plan
        .commit_plan()
        .expect("empty permanent boundary plan builds commit metadata");
    assert!(commit.commit_plan().object_copies().is_empty());
    assert!(commit.commit_plan().reference_rewrites().is_empty());
    assert!(
        commit
            .root_writeback_plan()
            .expect("empty root writeback metadata builds")
            .is_empty()
    );
}
