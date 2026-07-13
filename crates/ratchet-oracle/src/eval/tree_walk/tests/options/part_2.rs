//! Split-out tests (part_2). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn heap_memory_budget_tier_b_transition_admission_option_admits_owned_outcome() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("x: x");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
    // FV-3: generation rewrites live on record-table worker objects.
    options.set_record_worker_closures_for_gc_scaffolding(true);
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("lambda expression evaluates");
    let value = outcome.value();

    assert!(
        outcome
            .memory_budget_action()
            .expect("tree-walk outcome records configured budget action")
            .requests_tier_b()
    );
    assert_eq!(
        outcome
            .heap()
            .generation(value)
            .expect("lambda has a heap generation"),
        HeapGeneration::Old
    );
    let report = outcome
        .tier_b_transition_admission_report()
        .expect("automatic admission records its report");
    assert!(report.worker_records() > 0);
    assert_eq!(report.permanent_shared_records(), 0);
    assert_eq!(report.generation_rewrites(), report.worker_records());
    assert_eq!(
        outcome.stats().heap_tier_b_admission_worker_records(),
        report.worker_records() as u64
    );
    assert_eq!(
        outcome
            .stats()
            .heap_tier_b_admission_permanent_shared_records(),
        report.permanent_shared_records() as u64
    );
    assert_eq!(
        outcome.stats().heap_tier_b_admission_generation_rewrites(),
        report.generation_rewrites() as u64
    );
    let admission = outcome
        .tier_b_transition_admission_plan()
        .expect("current outcome heap still admits transition request")
        .expect("over-budget outcome has transition admission plan");
    assert!(admission.heap_plan().worker_records() > 0);
    assert!(
        admission
            .heap_plan()
            .records()
            .iter()
            .all(|record| !record.needs_generation_rewrite())
    );
}

#[test]
fn tier_b_transition_preflight_rejects_stale_worker_accounting() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("x: x");
    let outcome =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_heap_memory_budget(budget))
            .expect("lambda expression evaluates");

    let request = outcome
        .tier_b_transition_request()
        .expect("over-budget outcome requests Tier B transition");
    assert!(
        request.worker_stats().used_bytes > 0,
        "lambda fixture must allocate in the worker arena"
    );
    let stale_heap = EvalHeap::new();
    let error = request
        .preflight(&stale_heap)
        .expect_err("fresh heap has different worker arena accounting");
    assert_eq!(
        error,
        EvalTierBTransitionPreflightError::WorkerStatsChanged {
            expected: request.worker_stats(),
            actual: stale_heap.arena_stats(),
        }
    );
    let error = request
        .admission_plan(&stale_heap)
        .expect_err("fresh heap has different worker arena accounting");
    assert_eq!(
        error,
        EvalTierBTransitionAdmissionPlanError::Preflight(
            EvalTierBTransitionPreflightError::WorkerStatsChanged {
                expected: request.worker_stats(),
                actual: stale_heap.arena_stats(),
            }
        )
    );
}

#[test]
fn tier_b_transition_preflight_rejects_stale_permanent_shared_accounting() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("\"budgeted\"");
    let outcome =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_heap_memory_budget(budget))
            .expect("string evaluates");

    let request = outcome
        .tier_b_transition_request()
        .expect("over-budget outcome requests Tier B transition");
    let stale_heap = EvalHeap::new();
    let error = request
        .preflight(&stale_heap)
        .expect_err("fresh heap has different permanent-shared arena accounting");
    assert_eq!(
        error,
        EvalTierBTransitionPreflightError::PermanentSharedStatsChanged {
            expected: request.permanent_stats(),
            actual: stale_heap.permanent_arena_stats(),
        }
    );
    let error = request
        .admission_plan(&stale_heap)
        .expect_err("fresh heap has different permanent-shared arena accounting");
    assert_eq!(
        error,
        EvalTierBTransitionAdmissionPlanError::Preflight(
            EvalTierBTransitionPreflightError::PermanentSharedStatsChanged {
                expected: request.permanent_stats(),
                actual: stale_heap.permanent_arena_stats(),
            }
        )
    );
}

#[test]
fn heap_memory_budget_continuation_has_no_tier_b_transition_request() {
    let budget = HeapMemoryBudget::new(usize::MAX).expect("budget is non-zero");
    let ir = lower("\"budgeted\"");
    let mut outcome =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_heap_memory_budget(budget))
            .expect("string evaluates");

    let action = outcome
        .memory_budget_action()
        .expect("tree-walk outcome records configured budget action");
    assert!(!action.requests_tier_b());
    assert_eq!(outcome.tier_b_transition_request(), None);
    assert_eq!(outcome.tier_b_transition_admission_report(), None);
    assert_eq!(outcome.stats().heap_tier_b_admission_worker_records(), 0);
    assert_eq!(
        outcome.stats().heap_tier_b_admission_generation_rewrites(),
        0
    );
    assert_eq!(
        outcome
            .tier_b_transition_preflight()
            .expect("preflight checks are skipped without a transition request"),
        None
    );
    assert!(
        outcome
            .tier_b_transition_admission_plan()
            .expect("admission planning is skipped without a transition request")
            .is_none()
    );
    assert!(
        outcome
            .apply_tier_b_transition_admission_plan()
            .expect("admission application is skipped without a transition request")
            .is_none()
    );
    assert_eq!(outcome.tier_b_transition_admission_report(), None);
}

#[test]
fn heap_memory_budget_advice_has_no_tier_b_transition_request() {
    let baseline = eval_whnf_owned(&lower("\"budgeted\"")).expect("string evaluates");
    let resident_bytes = baseline
        .heap()
        .arena_stats()
        .mapped_bytes
        .saturating_add(baseline.heap().permanent_arena_stats().mapped_bytes);
    let budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");
    let mut outcome = eval_owned_with_options_and_heap_resident_memory_mode(
        "\"budgeted\"",
        TreeWalkOptions::with_heap_memory_budget(budget),
        EvalHeapResidentMemoryMode::ArenaMappedBytes,
    );

    let action = outcome
        .memory_budget_action()
        .expect("tree-walk outcome records configured budget action");
    let EvalHeapMemoryBudgetAction::AdviseUnusedTails { decision, .. } = action else {
        panic!("expected unused-tail advice action, got {action:?}");
    };
    assert_eq!(decision.budget(), budget);
    assert!(decision.requires_runtime_action());
    assert!(!action.requests_tier_b());
    assert_eq!(outcome.tier_b_transition_request(), None);
    assert_eq!(outcome.tier_b_transition_admission_report(), None);
    assert_eq!(outcome.stats().heap_tier_b_admission_worker_records(), 0);
    assert_eq!(
        outcome.stats().heap_tier_b_admission_generation_rewrites(),
        0
    );
    assert_eq!(
        outcome
            .tier_b_transition_preflight()
            .expect("preflight checks are skipped without a transition request"),
        None
    );
    assert!(
        outcome
            .tier_b_transition_admission_plan()
            .expect("admission planning is skipped without a transition request")
            .is_none()
    );
    assert!(
        outcome
            .apply_tier_b_transition_admission_plan()
            .expect("admission application is skipped without a transition request")
            .is_none()
    );
    assert_eq!(outcome.tier_b_transition_admission_report(), None);
}

#[test]
fn attr_path_eval_reports_final_heap_memory_budget_action() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("{ value = \"budgeted\"; }");
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"value".to_vec()],
        TreeWalkOptions::with_heap_memory_budget(budget),
        None,
    )
    .expect("attr-path selection evaluates");

    let action = outcome
        .memory_budget_action()
        .expect("attr-path outcome records configured budget action");
    assert_eq!(outcome.heap().last_memory_budget_action(), Some(action));
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().permanent_stats(),
        outcome.heap().permanent_arena_stats()
    );
    assert!(action.requests_tier_b());
    let transition = outcome
        .tier_b_transition_request()
        .expect("attr-path over-budget outcome requests Tier B transition");
    assert_eq!(transition.action(), action);
    assert_eq!(transition.decision(), action.decision());
    assert!(action.decision().requires_runtime_action());
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn attr_path_eval_tier_b_transition_admission_option_admits_selected_value() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("{ value = x: x; }");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
    // FV-3: generation rewrites live on record-table worker objects.
    options.set_record_worker_closures_for_gc_scaffolding(true);
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"value".to_vec()],
        options,
        None,
    )
    .expect("attr-path selection evaluates");

    assert!(
        outcome
            .memory_budget_action()
            .expect("attr-path outcome records configured budget action")
            .requests_tier_b()
    );
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("selected lambda has a heap generation"),
        HeapGeneration::Old
    );
    let report = outcome
        .tier_b_transition_admission_report()
        .expect("automatic attr-path admission records its report");
    assert!(report.worker_records() > 0);
    assert_eq!(report.generation_rewrites(), report.worker_records());
    assert_eq!(
        outcome.stats().heap_tier_b_admission_worker_records(),
        report.worker_records() as u64
    );
    assert_eq!(
        outcome.stats().heap_tier_b_admission_generation_rewrites(),
        report.generation_rewrites() as u64
    );
}

#[test]
fn gc_stress_policy_option_can_be_configured() {
    let policy = GcStressPolicy::every_n_safepoints(2).expect("period is non-zero");
    let mut options = TreeWalkOptions::new();

    assert!(options.gc_stress_policy().is_disabled());
    options.set_gc_stress_policy(policy);
    assert_eq!(options.gc_stress_policy(), policy);
    options.clear_gc_stress_policy();
    assert!(options.gc_stress_policy().is_disabled());

    let options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    assert_eq!(
        options.gc_stress_policy(),
        GcStressPolicy::every_safepoint()
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_policy_option_marks_tree_walk_heap_allocation_safepoints() {
    let policy = GcStressPolicy::every_safepoint();
    let default_worker =
        eval_whnf_owned(&lower("x: x")).expect("lambda expression evaluates without stress");
    let worker_outcome = eval_whnf_owned_with_options(
        &lower("x: x"),
        TreeWalkOptions::with_gc_stress_policy(policy),
    )
    .expect("lambda expression evaluates");

    assert_eq!(worker_outcome.value().tag(), default_worker.value().tag());
    assert_eq!(worker_outcome.heap().allocator_gc_stress_policy(), policy);
    assert_eq!(
        worker_outcome.heap().permanent_allocator_gc_stress_policy(),
        policy
    );
    let worker_safepoint = worker_outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("worker allocation safepoint records");
    assert_eq!(
        worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );

    let default_permanent =
        eval_whnf_owned(&lower("\"stress\"")).expect("string expression evaluates without stress");
    let permanent_outcome = eval_whnf_owned_with_options(
        &lower("\"stress\""),
        TreeWalkOptions::with_gc_stress_policy(policy),
    )
    .expect("string expression evaluates");
    assert_eq!(
        permanent_outcome
            .heap()
            .get_string(permanent_outcome.value())
            .expect("stress result is heap-owned string")
            .bytes(),
        default_permanent
            .heap()
            .get_string(default_permanent.value())
            .expect("default result is heap-owned string")
            .bytes()
    );
    let permanent_safepoint = permanent_outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("permanent allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_lambda_allocation_dispatches_reserved_writeback_bridge() {
    let ir = lower("x: x");
    let default_outcome = eval_whnf_owned(&ir).expect("default lambda evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress lambda evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Lambda);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("lambda generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(outcome.heap().len(), default_outcome.heap().len() + 1);
    let source_value = outcome
        .heap()
        .test_record_value(0)
        .expect("original lambda source record exists")
        .expect("original lambda source value rebuilds");
    let destination_value = outcome
        .heap()
        .test_record_value(1)
        .expect("reserved lambda destination record exists")
        .expect("reserved lambda destination value rebuilds");
    assert!(!source_value.raw_eq(outcome.value()));
    assert!(destination_value.raw_eq(outcome.value()));
    assert_eq!(
        outcome.heap().allocation_safepoints().count(),
        default_outcome.heap().allocation_safepoints().count() + 1
    );
    let final_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("final lambda reserved allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

#[test]
fn gc_stress_eval_root_string_allocation_dispatches_permanent_noop_bridge() {
    let ir = lower("\"gc-stress-root-string\"");
    let default_outcome = eval_whnf_owned(&ir).expect("default string evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress string evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::String);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("string generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("string is heap-owned")
            .bytes(),
        b"gc-stress-root-string"
    );
    assert_eq!(outcome.heap().len(), default_outcome.heap().len());
    assert_eq!(
        outcome.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count()
    );
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root string allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_alloc_static_string_helper_dispatches_permanent_noop_bridge() {
    let ir = lower("builtins.nixVersion");
    let span = Span::new(0, 0);
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_static_string(ir.root, span, PINNED_NIX_VERSION)
        })
        .expect("static helper string allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(!roots[0].raw_eq(local_source));
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(
        evaluator
            .heap()
            .generation(roots[0])
            .expect("registered root generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("static helper string generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        evaluator
            .heap()
            .get_string(value)
            .expect("static helper string is heap-owned")
            .bytes(),
        PINNED_NIX_VERSION
    );
    assert_eq!(evaluator.heap().len(), 3);
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[RuntimeAllocationEntryPoint::AosAllocString],
        "static string helper should dispatch exactly one permanent string allocation"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("static helper string allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_static_builtin_string_results_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches("builtins.nixVersion", PINNED_NIX_VERSION);
    assert_gc_stress_root_string_result_dispatches("builtins.storeDir", b"/nix/store");
    assert_gc_stress_root_string_result_dispatches_with_options(
        "builtins.currentSystem",
        b"x86_64-linux",
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
            .expect("currentSystem configures"),
    );
    assert_gc_stress_root_string_result_dispatches_with_options(
        r#"builtins.getEnv "AOS_RFC0007_STATIC_STRING""#,
        b"configured-env",
        TreeWalkOptions::with_env_var(
            b"AOS_RFC0007_STATIC_STRING".to_vec(),
            b"configured-env".to_vec(),
        ),
    );
    assert_gc_stress_root_string_result_dispatches_with_options(
        r#"builtins.getEnv "AOS_RFC0007_STATIC_STRING""#,
        b"",
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_type_of_static_string_results_dispatch_or_skip_composites() {
    let dispatch_cases: &[(&str, &[u8])] = &[
        ("builtins.typeOf 1", b"int"),
        ("builtins.typeOf 1.0", b"float"),
        ("builtins.typeOf false", b"bool"),
        ("builtins.typeOf null", b"null"),
        (r#"builtins.typeOf "x""#, b"string"),
        ("builtins.typeOf /tmp", b"path"),
        ("builtins.typeOf (x: x)", b"lambda"),
        ("builtins.typeOf builtins.length", b"lambda"),
        ("builtins.typeOf (builtins.map (x: x))", b"lambda"),
    ];

    for (source, expected) in dispatch_cases {
        assert_gc_stress_root_string_result_dispatches(source, expected);
    }

    let skip_cases: &[(&str, &[u8])] = &[
        ("builtins.typeOf [ 1 ]", b"list"),
        ("builtins.typeOf { a = 1; }", b"set"),
    ];

    for (source, expected) in skip_cases {
        assert_gc_stress_root_string_result_skips_dispatch(source, expected);
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_parse_drv_name_result_strings_dispatch_before_attrset_skip() {
    let ir = lower(r#"builtins.parseDrvName "foo-1.2""#);
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("parseDrvName argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let argument_value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"foo-1.2".to_vec()))
        .expect("argument string allocates");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, root.span, &mut roots, |eval| {
            eval.eval_parse_drv_name_primop(
                ir.root,
                root.span,
                argument,
                argument_span,
                argument_value,
            )
        })
        .expect("GC-stress parseDrvName evaluates");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while parseDrvName result strings allocated"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let name_key = evaluator.symbols.intern(b"name").expect("name key interns");
    let version_key = evaluator
        .symbols
        .intern(b"version")
        .expect("version key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("parseDrvName result is heap-owned");
    assert_eq!(
        evaluator
            .heap()
            .get_string(attrs.get(name_key).expect("name attr exists"))
            .expect("name string is heap-owned")
            .bytes(),
        b"foo"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_string(attrs.get(version_key).expect("version attr exists"))
            .expect("version string is heap-owned")
            .bytes(),
        b"1.2"
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "parseDrvName should dispatch the name/version string safepoints but not the final generated attrset"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 3,
        "parseDrvName should allocate exactly the name string, version string, and final attrset under GC stress"
    );
    let final_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("parseDrvName final attrset allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

