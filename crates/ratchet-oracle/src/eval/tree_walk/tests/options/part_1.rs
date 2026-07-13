//! Split-out tests (part_1). See parent module.

use super::*;

// Baseline float/scalar ABI test; variant float path via scalars.rs + parity
// battery (cutover plan section 7).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn evaluates_inline_scalar_literals() {
    assert_eq!(eval("42").as_int(), Ok(42));
    assert_eq!(eval("true").as_bool(), Ok(true));
    assert_eq!(eval("false").as_bool(), Ok(false));
    assert_eq!(eval("null").as_null(), Ok(()));

    let float = eval("1.25").as_float().expect("float value");
    assert_eq!(float.to_bits(), 1.25f64.to_bits());
}

#[test]
fn evaluates_string_literals_with_owned_heap() {
    let ir = lower("\"hello\"");
    let outcome = eval_whnf_owned(&ir).expect("string evaluates");
    let value = outcome.value();

    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        outcome
            .heap()
            .get_string(value)
            .expect("string is heap-owned")
            .bytes(),
        b"hello"
    );

    let empty = eval_whnf_owned(&lower("\"\"")).expect("empty string evaluates");
    assert_eq!(
        empty
            .heap()
            .get_string(empty.value())
            .expect("empty string is heap-owned")
            .bytes(),
        b""
    );

    let escaped =
        eval_whnf_owned(&lower("\"line\\n\\\"quoted\\\"\"")).expect("escaped string evaluates");
    assert_eq!(
        escaped
            .heap()
            .get_string(escaped.value())
            .expect("escaped string is heap-owned")
            .bytes(),
        b"line\n\"quoted\""
    );
}

#[test]
fn evaluates_uri_literals_as_strings() {
    assert_eq!(
        eval_string_bytes("https://example.test/path?x=1"),
        b"https://example.test/path?x=1"
    );
    assert_eq!(
        eval_string_bytes("https://example.test/path#fragment"),
        b"https://example.test/path"
    );
    assert_eq!(
        eval_string_bytes("https://example.test + \"/more\""),
        b"https://example.test/more"
    );
    assert_eq!(
        eval("https://example.test == \"https://example.test\"").as_bool(),
        Ok(true)
    );
}

#[test]
fn eval_cache_option_defaults_off_and_can_be_enabled() {
    let mut options = TreeWalkOptions::new();

    assert!(!options.eval_cache_enabled());
    options.set_eval_cache_enabled(true);
    assert!(options.eval_cache_enabled());

    let options = TreeWalkOptions::with_eval_cache_enabled(true);
    assert!(options.eval_cache_enabled());
}

#[test]
fn parallel_thunk_payloads_option_controls_tree_walk_thunk_allocations() {
    let mut options = TreeWalkOptions::new();
    let worker = ParallelThunkWorkerId::new(7).expect("test worker id is encodable");

    assert!(!options.parallel_thunk_payloads_enabled());
    assert_eq!(
        options.parallel_thunk_worker_id(),
        ParallelThunkWorkerId::FIRST
    );
    options.set_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(worker);
    assert!(options.parallel_thunk_payloads_enabled());
    assert_eq!(options.parallel_thunk_worker_id(), worker);

    let options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    assert!(options.parallel_thunk_payloads_enabled());
    assert_eq!(
        options.parallel_thunk_worker_id(),
        ParallelThunkWorkerId::FIRST
    );

    let options = TreeWalkOptions::with_parallel_thunk_worker_id(worker);
    assert!(!options.parallel_thunk_payloads_enabled());
    assert_eq!(options.parallel_thunk_worker_id(), worker);

    assert_eq!(
        attr_thunk_storage_mode("{ x = 1 / 0; }", b"x", TreeWalkOptions::new()),
        EvalThunkForceStorageMode::Serial
    );

    assert_eq!(
        attr_thunk_storage_mode(
            "{ x = 1 / 0; }",
            b"x",
            TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
        ),
        EvalThunkForceStorageMode::SerialWithParallelPayload
    );
    assert_eq!(
        list_thunk_storage_mode(
            "builtins.map (x: x + 1) [ 1 ]",
            0,
            TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
        ),
        EvalThunkForceStorageMode::SerialWithParallelPayload
    );
    assert_eq!(
        attr_thunk_storage_mode(
            "builtins.mapAttrs (_name: value: value + 1) { a = 1; }",
            b"a",
            TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
        ),
        EvalThunkForceStorageMode::SerialWithParallelPayload
    );
    assert_eq!(
        attr_thunk_storage_mode(
            "let source = { y = 1; }; in { inherit (source) y; }",
            b"y",
            TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
        ),
        EvalThunkForceStorageMode::SerialWithParallelPayload
    );
    assert_eq!(
        attr_thunk_storage_mode(
            "builtins",
            b"nixPath",
            TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
        ),
        EvalThunkForceStorageMode::SerialWithParallelPayload
    );
}

#[test]
fn parallel_thunk_worker_id_option_controls_payload_claim_identity() {
    let worker = ParallelThunkWorkerId::new(7).expect("test worker id is encodable");
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(worker);

    let (_ir, evaluator, thunk_value) = attr_thunk_value("{ x = 1 + 2; }", b"x", options.clone());
    assert_eq!(options.parallel_thunk_worker_id(), worker);

    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("root attr value is a heap thunk");
    let parallel_cell = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell is attached");
    let TreeWalkParallelThunkWait::Claimed(guard) = parallel_cell
        .claim_or_wait_for_result(options.parallel_thunk_worker_id())
        .expect("configured worker claims payload cell")
    else {
        panic!("fresh parallel payload cell should be claimable");
    };
    let TreeWalkParallelThunkWait::SelfCycle { owner } = parallel_cell
        .claim_or_wait_for_result(options.parallel_thunk_worker_id())
        .expect("configured worker re-entry is classified")
    else {
        panic!("same configured worker should report self-cycle");
    };
    assert_eq!(owner, worker);
    guard
        .publish_value(Value::int(3))
        .expect("configured worker publishes forced payload");
}

#[test]
fn parallel_thunk_worker_id_option_publishes_sidecar_with_configured_owner() {
    let worker = ParallelThunkWorkerId::new(7).expect("test worker id is encodable");
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(worker);
    let (_ir, evaluator, thunk_value) = attr_thunk_value("{ x = 1 + 2; }", b"x", options);

    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("root attr value is a heap thunk");
    let parallel_cell = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell is attached");
    let TreeWalkParallelThunkWait::Claimed(guard) = parallel_cell
        .claim_or_wait_for_result(worker)
        .expect("configured worker claims payload cell")
    else {
        panic!("fresh parallel payload cell should be claimable");
    };
    let publish = guard
        .publish_result(Ok(Value::int(3)))
        .expect("sidecar forced value publishes");
    assert_eq!(publish.owner(), worker);

    let terminal = parallel_cell
        .terminal_result()
        .expect("parallel payload stores terminal result")
        .expect("parallel terminal result is successful");
    assert_eq!(terminal.as_int(), Ok(3));
}

#[test]
fn parallel_thunk_payload_ready_value_bypasses_serial_suspended_force() {
    let (ir, mut evaluator, thunk_value) = attr_thunk_value(
        "{ x = 1 + 2; }",
        b"x",
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );

    {
        let thunk = evaluator
            .heap
            .clone_thunk(thunk_value)
            .expect("root attr value is a heap thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        let parallel_cell = thunk
            .parallel_payload_cell()
            .expect("parallel payload cell is attached");
        let worker = ParallelThunkWorkerId::new(1).expect("test worker id is encodable");
        let TreeWalkParallelThunkWait::Claimed(guard) = parallel_cell
            .claim_or_wait_for_result(worker)
            .expect("parallel payload cell can be claimed")
        else {
            panic!("fresh parallel payload cell should be claimable");
        };
        guard
            .publish_value(Value::int(99))
            .expect("forced sidecar payload publishes");
    }

    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("parallel payload replay succeeds");
    assert_eq!(forced.as_int(), Ok(99));
    assert_eq!(evaluator.stats().thunks_forced(), 0);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 1);

    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("root attr value is a heap thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    let terminal = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell remains attached")
        .terminal_result()
        .expect("parallel payload remains terminal")
        .expect("parallel terminal result is successful");
    assert_eq!(terminal.as_int(), Ok(99));
}

#[test]
fn parallel_thunk_payload_failed_result_bypasses_serial_suspended_force() {
    let expected = TreeWalkError::new(
        TreeWalkErrorKind::DivisionByZero { id: IrId::new(13) },
        Span::new(13, 14),
    );
    let (ir, mut evaluator, thunk_value) = attr_thunk_value(
        "{ x = 1 + 2; }",
        b"x",
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );

    {
        let thunk = evaluator
            .heap
            .clone_thunk(thunk_value)
            .expect("root attr value is a heap thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        let parallel_cell = thunk
            .parallel_payload_cell()
            .expect("parallel payload cell is attached");
        let worker = ParallelThunkWorkerId::new(1).expect("test worker id is encodable");
        let TreeWalkParallelThunkWait::Claimed(guard) = parallel_cell
            .claim_or_wait_for_result(worker)
            .expect("parallel payload cell can be claimed")
        else {
            panic!("fresh parallel payload cell should be claimable");
        };
        guard
            .publish_error(expected.clone())
            .expect("failed sidecar payload publishes");
    }

    let error = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("parallel failed payload replay returns stored error");
    assert_eq!(error, expected);
    assert_eq!(evaluator.stats().thunks_forced(), 0);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);

    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("root attr value is a heap thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    let terminal = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell remains attached")
        .terminal_result()
        .expect("parallel payload remains terminal")
        .expect_err("parallel terminal result is failed");
    assert_eq!(terminal, expected);
}

#[test]
fn parallel_thunk_payload_same_worker_claim_reports_recursion_without_serial_force() {
    let (ir, mut evaluator, thunk_value) = attr_thunk_value(
        "{ x = 1 + 2; }",
        b"x",
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );
    let worker = evaluator.options.parallel_thunk_worker_id();
    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("root attr value is a heap thunk");
    let parallel_cell = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell is attached");
    let TreeWalkParallelThunkWait::Claimed(_guard) = parallel_cell
        .claim_or_wait_for_result(worker)
        .expect("configured worker claims payload cell")
    else {
        panic!("fresh parallel payload cell should be claimable");
    };

    let error = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("same-worker sidecar claim is reported as recursion");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Force {
            source: ForceError::InfiniteRecursion,
            ..
        }
    ));
    assert_eq!(evaluator.stats().thunks_forced(), 0);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(
        parallel_cell.state().expect("parallel state loads"),
        ParallelThunkTerminalStatus::Claimed
    );
}

#[test]
fn parallel_thunk_payload_success_replays_after_serial_force() {
    let mut options = TreeWalkOptions::with_parallel_thunk_payloads_enabled(true);
    options.set_parallel_thunk_worker_id(
        ParallelThunkWorkerId::new(7).expect("test worker id is encodable"),
    );
    let (ir, mut evaluator, thunk_value) = attr_thunk_value("{ x = 1 + 2; }", b"x", options);

    {
        let thunk = evaluator
            .heap
            .clone_thunk(thunk_value)
            .expect("root attr value is a heap thunk");
        let parallel_cell = thunk
            .parallel_payload_cell()
            .expect("parallel payload cell is attached");
        assert_eq!(
            parallel_cell.state().expect("parallel state loads"),
            ParallelThunkTerminalStatus::Suspended
        );
        assert!(parallel_cell.terminal_result().is_none());
    }

    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.as_int(), Ok(3));
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);

    {
        let thunk = evaluator
            .heap
            .clone_thunk(thunk_value)
            .expect("root attr value is a heap thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
        let parallel_cell = thunk
            .parallel_payload_cell()
            .expect("parallel payload cell remains attached");
        assert_eq!(
            parallel_cell.state().expect("parallel state loads"),
            ParallelThunkTerminalStatus::Forced
        );
        let terminal = parallel_cell
            .terminal_result()
            .expect("parallel payload stores terminal result")
            .expect("parallel terminal result is successful");
        assert_eq!(terminal.as_int(), Ok(3));
    }

    let replay = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("parallel payload replay succeeds");
    assert_eq!(replay.as_int(), Ok(3));
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 1);
}

#[test]
fn parallel_thunk_payload_force_errors_publish_failed_replay() {
    let (ir, mut evaluator, thunk_value) = attr_thunk_value(
        "{ x = 1 / 0; }",
        b"x",
        TreeWalkOptions::with_parallel_thunk_payloads_enabled(true),
    );

    let first = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("division by zero remains a force error");
    assert!(matches!(
        first.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);

    {
        let thunk = evaluator
            .heap
            .clone_thunk(thunk_value)
            .expect("root attr value is a heap thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        let parallel_cell = thunk
            .parallel_payload_cell()
            .expect("parallel payload cell remains attached");
        assert_eq!(
            parallel_cell.state().expect("parallel state loads"),
            ParallelThunkTerminalStatus::Failed
        );
        assert_eq!(
            parallel_cell
                .terminal_result()
                .expect("parallel terminal result is stored")
                .expect_err("parallel terminal result is failed"),
            first
        );
    }

    let second = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect_err("division by zero is replayed through the failed sidecar");
    assert_eq!(second, first);
    assert_eq!(evaluator.stats().thunks_forced(), 1);
    assert_eq!(evaluator.stats().thunk_cache_hits(), 0);

    let thunk = evaluator
        .heap
        .clone_thunk(thunk_value)
        .expect("root attr value is a heap thunk");
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    let parallel_cell = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell remains attached");
    assert_eq!(
        parallel_cell.state().expect("parallel state loads"),
        ParallelThunkTerminalStatus::Failed
    );
    assert_eq!(
        parallel_cell
            .terminal_result()
            .expect("parallel terminal result remains stored")
            .expect_err("parallel terminal result remains failed"),
        first
    );
}

#[test]
fn heap_memory_budget_option_can_be_configured() {
    let budget = HeapMemoryBudget::new(4096).expect("budget is non-zero");
    let mut options = TreeWalkOptions::new();

    assert_eq!(options.heap_memory_budget(), None);
    options.set_heap_memory_budget(budget);
    assert_eq!(options.heap_memory_budget(), Some(budget));
    options.clear_heap_memory_budget();
    assert_eq!(options.heap_memory_budget(), None);

    let options = TreeWalkOptions::with_heap_memory_budget(budget);
    assert_eq!(options.heap_memory_budget(), Some(budget));
}

#[test]
fn heap_tier_b_transition_admission_option_can_be_configured() {
    let mut options = TreeWalkOptions::new();

    assert!(!options.heap_tier_b_transition_admission_enabled());
    options.set_heap_tier_b_transition_admission_enabled(true);
    assert!(options.heap_tier_b_transition_admission_enabled());
    options.set_heap_tier_b_transition_admission_enabled(false);
    assert!(!options.heap_tier_b_transition_admission_enabled());

    let options = TreeWalkOptions::with_heap_tier_b_transition_admission_enabled(true);
    assert!(options.heap_tier_b_transition_admission_enabled());
}

#[test]
fn heap_thread_local_tier_a_option_routes_tree_walk_worker_allocations() {
    let mut options = TreeWalkOptions::new();

    assert!(!options.heap_thread_local_tier_a_enabled());
    options.set_heap_thread_local_tier_a_enabled(true);
    assert!(options.heap_thread_local_tier_a_enabled());
    options.set_heap_thread_local_tier_a_enabled(false);
    assert!(!options.heap_thread_local_tier_a_enabled());

    let ir = lower("\"thread-local\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_heap_thread_local_tier_a_enabled(true),
    )
    .expect("string evaluates");

    assert!(outcome.heap().uses_thread_local_tier_a());
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("string is heap-owned")
            .bytes(),
        b"thread-local"
    );
}

#[test]
fn heap_thread_local_tier_a_option_starts_each_owned_eval_from_empty_worker_arena() {
    let ir = lower("\"thread-local\"");

    {
        let mut stale = RuntimeAllocator::tier_a_thread_local();
        stale
            .aos_alloc_string(12)
            .expect("stale thread-local allocation succeeds");
        assert!(stale.stats().used_bytes > 0);
    }

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_heap_thread_local_tier_a_enabled(true),
    )
    .expect("string evaluates");
    assert!(outcome.heap().uses_thread_local_tier_a());
    assert_eq!(outcome.heap().arena_stats().used_bytes, 0);
}

#[test]
fn heap_memory_budget_option_polls_tree_walk_heap_allocations() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("\"budgeted\"");
    let outcome =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_heap_memory_budget(budget))
            .expect("string evaluates");

    assert_eq!(outcome.heap().memory_budget(), Some(budget));
    assert_eq!(
        outcome.heap().resident_memory_mode(),
        EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback
    );
    assert_eq!(outcome.heap().memory_budget_poll_count(), 1);
    let action = outcome
        .memory_budget_action()
        .expect("tree-walk outcome records configured budget action");
    assert_eq!(outcome.heap().last_memory_budget_action(), Some(action));
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().worker_stats(),
        outcome.heap().arena_stats()
    );
    assert_eq!(
        action.decision().permanent_stats(),
        outcome.heap().permanent_arena_stats()
    );
    match action.decision().resident_source() {
        EvalHeapResidentMemorySource::ArenaMappedBytes => {}
        EvalHeapResidentMemorySource::ProcessResidentSet(_) => {}
    }
    assert!(action.requests_tier_b());
    let transition = outcome
        .tier_b_transition_request()
        .expect("over-budget outcome requests Tier B transition");
    assert_eq!(transition.action(), action);
    assert_eq!(transition.decision(), action.decision());
    assert_eq!(transition.worker_stats(), outcome.heap().arena_stats());
    assert_eq!(
        transition.permanent_stats(),
        outcome.heap().permanent_arena_stats()
    );
    assert_eq!(transition.advice_report(), action.advice_report().unwrap());
    assert_eq!(
        transition.pre_flip_mapped_bytes(),
        transition
            .worker_stats()
            .mapped_bytes
            .saturating_add(transition.permanent_stats().mapped_bytes)
    );
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn heap_memory_budget_tier_b_transition_preflight_admits_current_heap() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("\"budgeted\"");
    let outcome =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_heap_memory_budget(budget))
            .expect("string evaluates");

    let request = outcome
        .tier_b_transition_request()
        .expect("over-budget outcome requests Tier B transition");
    let preflight = outcome
        .tier_b_transition_preflight()
        .expect("current outcome heap matches transition request")
        .expect("over-budget outcome has transition preflight");
    assert_eq!(preflight.request(), request);
    assert_eq!(
        preflight.pre_flip_mapped_bytes(),
        request.pre_flip_mapped_bytes()
    );
    assert_eq!(
        preflight.worker().domain(),
        EvalTierBTransitionDomain::Worker
    );
    assert_eq!(preflight.worker().stats(), outcome.heap().arena_stats());
    assert_eq!(preflight.worker().generation(), HeapGeneration::Old);
    assert_eq!(
        preflight.permanent_shared().domain(),
        EvalTierBTransitionDomain::PermanentShared
    );
    assert_eq!(
        preflight.permanent_shared().stats(),
        outcome.heap().permanent_arena_stats()
    );
    assert_eq!(
        preflight.permanent_shared().generation(),
        HeapGeneration::Permanent
    );
    assert_eq!(
        preflight.domains(),
        [preflight.worker(), preflight.permanent_shared()]
    );
    let admission = outcome
        .tier_b_transition_admission_plan()
        .expect("current outcome heap admits transition request")
        .expect("over-budget outcome has transition admission plan");
    assert_eq!(admission.preflight(), preflight);
    assert_eq!(admission.request(), request);
    assert_eq!(
        admission.pre_flip_mapped_bytes(),
        request.pre_flip_mapped_bytes()
    );
    assert_eq!(
        admission.heap_plan().worker_stats(),
        outcome.heap().arena_stats()
    );
    assert_eq!(
        admission.heap_plan().permanent_stats(),
        outcome.heap().permanent_arena_stats()
    );
    assert_eq!(
        admission.heap_plan().record_count(),
        outcome.heap().record_count()
    );
    assert_eq!(
        admission
            .heap_plan()
            .worker_records()
            .saturating_add(admission.heap_plan().permanent_shared_records()),
        admission.heap_plan().record_count()
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn heap_memory_budget_tier_b_transition_application_admits_worker_records() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("x: x");
    // FV-3: generation rewrites live on record-table worker objects, so
    // this fixture selects the Tier-B B2 scaffolding placement.
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_record_worker_closures_for_gc_scaffolding(true);
    let mut outcome =
        eval_whnf_owned_with_options(&ir, options).expect("lambda expression evaluates");
    let value = outcome.value();

    assert_eq!(
        outcome
            .heap()
            .generation(value)
            .expect("lambda has a heap generation"),
        HeapGeneration::Young
    );
    assert_eq!(outcome.tier_b_transition_admission_report(), None);
    assert_eq!(outcome.stats().heap_tier_b_admission_worker_records(), 0);
    assert_eq!(
        outcome
            .stats()
            .heap_tier_b_admission_permanent_shared_records(),
        0
    );
    assert_eq!(
        outcome.stats().heap_tier_b_admission_generation_rewrites(),
        0
    );
    let report = outcome
        .apply_tier_b_transition_admission_plan()
        .expect("transition admission applies")
        .expect("over-budget outcome has transition admission");
    assert!(report.worker_records() > 0);
    assert_eq!(report.permanent_shared_records(), 0);
    assert_eq!(report.generation_rewrites(), report.worker_records());
    assert_eq!(
        outcome
            .heap()
            .generation(value)
            .expect("lambda has a heap generation"),
        HeapGeneration::Old
    );
    assert_eq!(outcome.tier_b_transition_admission_report(), Some(report));
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
}

