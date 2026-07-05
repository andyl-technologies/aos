//! Tree-walk evaluator tests: options.

use super::*;
use crate::eval::heap::EvalThunkForceStorageMode;
use crate::eval::heap::{
    EvalHeap, EvalHeapMemoryBudgetAction, EvalHeapResidentMemoryMode, EvalHeapResidentMemorySource,
};
use crate::eval::{
    EvalThunk, ForceError, ParallelThunkTerminalStatus, ParallelThunkWorkerId,
    TreeWalkParallelThunkWait,
};
use crate::heap::{HeapGeneration, HeapMemoryBudgetResponse, MemoryAdviceKind};
use crate::runtime::alloc::{
    AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint, RuntimeAllocator,
};

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
    let (ir, evaluator, thunk_value) = attr_thunk_value("{ x = 1 + 2; }", b"x", options);

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
    let publish = evaluator
        .publish_parallel_payload_claim_result(ir.root, Span::new(0, 0), guard, Ok(Value::int(3)))
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

fn attr_thunk_storage_mode(
    source: &str,
    attr: &[u8],
    options: TreeWalkOptions,
) -> EvalThunkForceStorageMode {
    let (_ir, evaluator, value) = attr_thunk_value(source, attr, options);

    storage_mode_for_thunk_value(&evaluator, value)
}

fn attr_thunk_value(source: &str, attr: &[u8], options: TreeWalkOptions) -> (Ir, TreeWalk, Value) {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator
        .eval_root()
        .expect("source evaluates to an attrset");
    let attr = evaluator.symbols.intern(attr).expect("attr symbol interns");
    let value = evaluator
        .heap
        .get_attrs(value)
        .expect("root value is a heap attrset")
        .get(attr)
        .expect("attr exists");

    (ir, evaluator, value)
}

fn list_thunk_storage_mode(
    source: &str,
    index: usize,
    options: TreeWalkOptions,
) -> EvalThunkForceStorageMode {
    let ir = lower(source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("source evaluates to a list");
    let value = *evaluator
        .heap
        .get_list(value)
        .expect("root value is a heap list")
        .as_slice()
        .get(index)
        .expect("list element exists");

    storage_mode_for_thunk_value(&evaluator, value)
}

fn storage_mode_for_thunk_value(evaluator: &TreeWalk, value: Value) -> EvalThunkForceStorageMode {
    assert_eq!(value.tag(), ValueTag::Thunk);
    evaluator
        .heap
        .clone_thunk(value)
        .expect("root value is a heap thunk")
        .force_storage_mode()
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
    assert_eq!(admission.heap_plan().record_count(), outcome.heap().len());
    assert_eq!(
        admission
            .heap_plan()
            .worker_records()
            .saturating_add(admission.heap_plan().permanent_shared_records()),
        admission.heap_plan().record_count()
    );
}

#[test]
fn heap_memory_budget_tier_b_transition_application_admits_worker_records() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("x: x");
    let mut outcome =
        eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_heap_memory_budget(budget))
            .expect("lambda expression evaluates");
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

#[test]
fn heap_memory_budget_tier_b_transition_admission_option_admits_owned_outcome() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("x: x");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
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

#[test]
fn attr_path_eval_tier_b_transition_admission_option_admits_selected_value() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("{ value = x: x; }");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_tier_b_transition_admission_enabled(true);
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

#[test]
fn gc_stress_alloc_symbol_string_helper_skips_unregistered_local_dispatch() {
    let ir = lower("{ helperSymbol = 1; }");
    let span = Span::new(0, 0);
    let symbol = symbol_for(&ir, b"helperSymbol");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_symbol_string(ir.root, span, symbol)
        })
        .expect("symbol helper string allocates without dispatching");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(roots[0].raw_eq(local_source));
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
            .expect("symbol helper string generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        evaluator
            .heap()
            .get_string(value)
            .expect("symbol helper string is heap-owned")
            .bytes(),
        b"helperSymbol"
    );
    assert_eq!(evaluator.heap().len(), 2);
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("symbol helper string allocation safepoint records");
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

#[test]
fn gc_stress_eval_root_uri_allocation_dispatches_permanent_noop_bridge() {
    let ir = lower("https://gc-stress.example.test/root");
    let default_outcome = eval_whnf_owned(&ir).expect("default URI evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress URI evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::String);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("URI string generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("URI string is heap-owned")
            .bytes(),
        b"https://gc-stress.example.test/root"
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
        .expect("root URI allocation safepoint records");
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

#[test]
fn gc_stress_eval_root_path_allocation_dispatches_permanent_noop_bridge() {
    let ir = lower("/tmp/gc-stress-root-path");
    let default_outcome = eval_whnf_owned(&ir).expect("default path evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress path evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Path);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("path generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        outcome
            .heap()
            .get_path(outcome.value())
            .expect("path is heap-owned")
            .bytes(),
        b"/tmp/gc-stress-root-path"
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
        .expect("root path allocation safepoint records");
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

fn assert_gc_stress_root_string_result_dispatches(source: &str, expected: &[u8]) {
    let ir = lower(source);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress root expression evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while evaluating {source}"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("string generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        evaluator
            .heap()
            .get_string(value)
            .expect("string is heap-owned")
            .bytes(),
        expected
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root string result allocation safepoint records");
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

fn assert_gc_stress_root_path_result_dispatches(source: &str, expected: &[u8]) {
    let ir = lower(source);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress root expression evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while evaluating {source}"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Path);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("path generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        evaluator
            .heap()
            .get_path(value)
            .expect("path is heap-owned")
            .bytes(),
        expected
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root path result allocation safepoint records");
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

#[test]
fn gc_stress_eval_root_unary_string_result_helpers_dispatch_permanent_noop_bridge() {
    let cases: &[(&str, &[u8])] = &[
        (
            r#"builtins.baseNameOf "/tmp/gc-stress-root-name""#,
            b"gc-stress-root-name",
        ),
        (r#"builtins.dirOf "/tmp/gc-stress-root-name""#, b"/tmp"),
        (
            r#"builtins.toPath "/tmp/../var/gc-stress-root-name""#,
            b"/var/gc-stress-root-name",
        ),
    ];

    for (source, expected) in cases {
        assert_gc_stress_root_string_result_dispatches(source, expected);
    }
}

#[test]
fn gc_stress_eval_root_unary_path_result_helpers_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_path_result_dispatches(
        "builtins.dirOf /tmp/gc-stress-root-name",
        b"/tmp",
    );
}

#[test]
fn gc_stress_eval_root_hash_string_result_helpers_dispatch_permanent_noop_bridge() {
    let cases: &[(&str, &[u8])] = &[
        (
            r#"builtins.hashString "sha256" "abc""#,
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            r#"builtins.placeholder "out""#,
            b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9",
        ),
    ];

    for (source, expected) in cases {
        assert_gc_stress_root_string_result_dispatches(source, expected);
    }
}

#[test]
fn gc_stress_eval_root_substring_string_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(r#"builtins.substring 1 2 "abcd""#, b"bc");
}

#[test]
fn gc_stress_context_string_result_helpers_dispatch_permanent_noop_bridge() {
    type ContextStringHelper =
        fn(&mut TreeWalk, IrId, Span, IrId, Span, Value) -> Result<Value, TreeWalkError>;
    let cases: &[(&str, ContextStringHelper)] = &[
        (
            "builtins.addDrvOutputDependencies \"x\"",
            TreeWalk::eval_add_drv_output_dependencies_primop,
        ),
        (
            "builtins.unsafeDiscardOutputDependency \"x\"",
            TreeWalk::eval_unsafe_discard_output_dependency_primop,
        ),
        (
            "builtins.unsafeDiscardStringContext \"x\"",
            TreeWalk::eval_unsafe_discard_string_context_primop,
        ),
    ];

    for (source, helper) in cases {
        let ir = lower(source);
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
            .expect("context helper argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::with_options(
            &ir,
            TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
        );
        let context_path = b"/nix/store/context.drv".to_vec();
        let source_element = if source.contains("unsafeDiscardOutputDependency") {
            ContextElement::deep_derivation(context_path).expect("source context builds")
        } else {
            ContextElement::opaque_path(context_path).expect("source context builds")
        };
        let source_context =
            StringContext::singleton(source_element).expect("source context allocates");
        let source_string = evaluator
            .heap
            .alloc_string(NixString::new(b"x".to_vec(), source_context))
            .expect("source string allocates");
        let local_source = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(7)))
            .expect("registered local thunk allocates");
        let mut roots = [local_source];

        evaluator.active_root_eval_node = Some(ir.root);
        let value = evaluator
            .with_transient_value_stack_roots(ir.root, root.span, &mut roots, |eval| {
                helper(
                    eval,
                    ir.root,
                    root.span,
                    argument,
                    argument_span,
                    source_string,
                )
            })
            .expect("context string helper evaluates under GC stress");
        evaluator.active_root_eval_node = None;

        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert!(
            !roots[0].raw_eq(local_source),
            "registered root was not relocated while evaluating {source}"
        );
        assert_eq!(roots[0].tag(), ValueTag::Thunk);
        assert_eq!(value.tag(), ValueTag::String);
        assert_eq!(
            evaluator
                .heap()
                .generation(value)
                .expect("context result string generation is known"),
            HeapGeneration::Permanent
        );
        assert_eq!(
            evaluator
                .heap()
                .get_string(value)
                .expect("context result string is heap-owned")
                .bytes(),
            b"x"
        );
        let permanent_safepoint = evaluator
            .heap()
            .permanent_allocation_safepoints()
            .last()
            .expect("context result string allocation safepoint records");
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
}

#[test]
fn gc_stress_lambda_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct lambda node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::Lambda);
    assert_eq!(evaluator.heap().len(), 1);
    assert_eq!(evaluator.heap().allocation_safepoints().count(), 1);
    let final_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct lambda allocation safepoint records");
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
fn gc_stress_eval_root_primop_allocation_dispatches_reserved_writeback_bridge() {
    let ir = lower("builtins.length");
    let default_outcome = eval_whnf_owned(&ir).expect("default primop evaluates");

    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let value = evaluator.eval_root().expect("GC-stress primop evaluates");

    assert_eq!(value.tag(), ValueTag::Primop);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("primop generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(evaluator.heap().len(), default_outcome.heap().len() + 1);
    let source_value = evaluator
        .heap()
        .test_record_value(0)
        .expect("original primop source record exists")
        .expect("original primop source value rebuilds");
    let destination_value = evaluator
        .heap()
        .test_record_value(1)
        .expect("reserved primop destination record exists")
        .expect("reserved primop destination value rebuilds");
    assert!(!source_value.raw_eq(value));
    assert!(destination_value.raw_eq(value));
    assert_eq!(
        evaluator.heap().allocation_safepoints().count(),
        default_outcome.heap().allocation_safepoints().count() + 1
    );
    let final_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("final primop reserved allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocRaw
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );

    let empty_list = evaluator
        .heap
        .alloc_list(NixList::empty())
        .expect("empty list allocates");
    let applied = evaluator
        .apply_value(ir.root, Span::new(0, 0), value, empty_list)
        .expect("relocated length primop applies");
    assert_eq!(applied.as_int(), Ok(0));
}

#[test]
fn gc_stress_primop_allocation_dispatch_skips_captured_argument_primops() {
    let ir = lower("builtins.substring \"abcdef\"");
    let default_outcome = eval_whnf_owned(&ir).expect("default partial primop evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress partial primop evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Primop);
    let primop = outcome
        .heap()
        .get_primop(outcome.value())
        .expect("partial primop is heap-owned");
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].value().tag(), ValueTag::String);
    assert_eq!(outcome.heap().len(), default_outcome.heap().len());
    assert_eq!(
        outcome.heap().allocation_safepoints().count(),
        default_outcome.heap().allocation_safepoints().count()
    );
    let final_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("partial primop allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocRaw
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

#[test]
fn gc_stress_primop_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("builtins.map");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct primop node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::Primop);
    assert_eq!(evaluator.heap().len(), 1);
    assert_eq!(evaluator.heap().allocation_safepoints().count(), 1);
    let final_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct primop allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocRaw
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

fn heap_record_values_with_tag(heap: &EvalHeap, tag: ValueTag) -> Vec<Value> {
    heap.test_record_values()
        .map(|value| value.expect("heap record value rebuilds"))
        .filter(|value| value.tag() == tag)
        .collect()
}

#[test]
fn gc_stress_eval_root_thunk_allocation_dispatches_reserved_forwarding_bridge() {
    let body = IrId::new(0);
    let root = IrId::new(1);
    let ir = manual_ir(
        root,
        vec![
            pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(7)),
            pure_node(IrKind::ThunkAlloc, Span::new(0, 1), IrData::Node(body)),
        ],
    );
    let default_outcome = eval_whnf_owned(&ir).expect("default root thunk alloc evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress root thunk alloc evaluates");

    assert_eq!(outcome.value().as_int(), Ok(7));
    assert_eq!(outcome.stats().thunks_allocated(), 1);
    assert_eq!(outcome.heap().len(), default_outcome.heap().len() + 1);
    let source_value = outcome
        .heap()
        .test_record_value(0)
        .expect("original thunk source record exists")
        .expect("original thunk source value rebuilds");
    let destination_value = outcome
        .heap()
        .test_record_value(1)
        .expect("reserved thunk destination record exists")
        .expect("reserved thunk destination value rebuilds");
    assert_eq!(source_value.tag(), ValueTag::Thunk);
    assert_eq!(destination_value.tag(), ValueTag::Thunk);
    assert!(!source_value.raw_eq(destination_value));
    assert_eq!(
        outcome
            .heap()
            .generation(destination_value)
            .expect("root thunk destination generation is known"),
        HeapGeneration::Young
    );
    assert_eq!(
        outcome.heap().allocation_safepoints().count(),
        default_outcome.heap().allocation_safepoints().count() + 1
    );
    let final_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("final root thunk reserved allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}

#[test]
fn gc_stress_eval_root_list_allocation_dispatches_dirty_card_writeback_bridge() {
    let ir = lower("[ (x: x) ]");
    let default_outcome = eval_whnf_owned(&ir).expect("default list evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress list evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::List);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("list generation is known"),
        HeapGeneration::Permanent
    );
    assert!(outcome.heap().len() > default_outcome.heap().len());

    let element = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root list is heap-owned");
        list.get(0).expect("list element exists")
    };
    assert_eq!(element.tag(), ValueTag::Thunk);
    assert_eq!(
        outcome
            .heap()
            .generation(element)
            .expect("element generation is known"),
        HeapGeneration::Young
    );
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert!(thunk_values.iter().any(|value| value.raw_eq(element)));
    assert!(
        thunk_values
            .iter()
            .filter(|value| !value.raw_eq(element))
            .count()
            >= 1
    );

    assert!(
        outcome.heap().allocation_safepoints().count()
            > default_outcome.heap().allocation_safepoints().count()
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("reserved thunk allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        outcome.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count()
    );
    let final_permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root list allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_list_allocation_dispatch_skips_local_accumulator_fields() {
    let ir = lower("[ (x: x) (y: y) ]");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress multi-element list evaluates without local accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::List);
    let elements = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("root list is heap-owned");
        vec![
            list.get(0).expect("first list element exists"),
            list.get(1).expect("second list element exists"),
        ]
    };
    for element in &elements {
        assert_eq!(element.tag(), ValueTag::Thunk);
        assert_eq!(
            outcome
                .heap()
                .generation(*element)
                .expect("element generation is known"),
            HeapGeneration::Young
        );
    }
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    for element in &elements {
        assert!(thunk_values.iter().any(|value| value.raw_eq(*element)));
    }
    assert!(
        thunk_values
            .iter()
            .filter(|value| !elements.iter().any(|element| value.raw_eq(*element)))
            .count()
            >= elements.len()
    );
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root list allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_list_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("[ (x: x) ]");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct list node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::List);
    let element = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("root list is heap-owned");
        list.get(0).expect("list element exists")
    };
    assert_eq!(element.tag(), ValueTag::Thunk);
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), 1);
    assert_eq!(
        thunk_values
            .iter()
            .filter(|value| value.raw_eq(element))
            .count(),
        1
    );
    assert!(evaluator.heap().allocation_safepoints().count() >= 1);
    let final_worker_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct list worker allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("direct list allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_eval_root_attrs_allocation_dispatches_dirty_card_writeback_bridge() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let default_outcome = eval_whnf_owned(&ir).expect("default attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress attrset evaluates");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    assert_eq!(
        outcome
            .heap()
            .generation(outcome.value())
            .expect("attrset generation is known"),
        HeapGeneration::Permanent
    );
    assert!(outcome.heap().len() > default_outcome.heap().len());

    let attr_value = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(attr_value.tag(), ValueTag::Thunk);
    assert_eq!(
        outcome
            .heap()
            .generation(attr_value)
            .expect("attr value generation is known"),
        HeapGeneration::Young
    );
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert!(thunk_values.iter().any(|value| value.raw_eq(attr_value)));
    assert!(
        thunk_values
            .iter()
            .filter(|value| !value.raw_eq(attr_value))
            .count()
            >= 1
    );

    assert!(
        outcome.heap().allocation_safepoints().count()
            > default_outcome.heap().allocation_safepoints().count()
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("reserved thunk allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        outcome.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count()
    );
    let final_permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root attrset allocation safepoint records");
    assert_eq!(
        final_permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_attrs_allocation_dispatch_skips_local_accumulator_fields() {
    let ir = lower("{ a = x: x; b = y: y; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress multi-attr attrset evaluates without local accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let attr_values = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    let values = [attr_values.0, attr_values.1];
    for value in values {
        assert_eq!(value.tag(), ValueTag::Thunk);
        assert_eq!(
            outcome
                .heap()
                .generation(value)
                .expect("attr value generation is known"),
            HeapGeneration::Young
        );
    }
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    for value in values {
        assert!(thunk_values.iter().any(|record| record.raw_eq(value)));
    }
    assert!(
        thunk_values
            .iter()
            .filter(|record| !values.iter().any(|value| record.raw_eq(*value)))
            .count()
            >= values.len()
    );
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_attrs_allocation_dispatch_skips_captured_lexical_env_fields() {
    let ir = lower("rec { a = b; b = x: x; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let default_outcome = eval_whnf_owned(&ir).expect("default recursive attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress recursive attrset evaluates without unsupported captured-env writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let (a_value, b_value) = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    assert_eq!(a_value.tag(), ValueTag::Thunk);
    assert_eq!(b_value.tag(), ValueTag::Thunk);
    let a_thunk = outcome
        .heap()
        .get_thunk(a_value)
        .expect("a is a heap-owned thunk");
    let b_thunk = outcome
        .heap()
        .get_thunk(b_value)
        .expect("b is a heap-owned thunk");
    assert!(a_thunk.env().is_some_and(|env| !env.frames().is_empty()));
    assert!(b_thunk.env().is_some_and(|env| !env.frames().is_empty()));

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
        .expect("recursive attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_thunk_allocation_dispatch_skips_active_lexical_env_frames() {
    let ir = lower("let r = rec { a = b; b = x: x; }; in { inherit (r) a; }");
    let a = symbol_for(&ir, b"a");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress inherited select evaluates without active-frame writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let selected = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(selected.tag(), ValueTag::Thunk);
    let selected_thunk = outcome
        .heap()
        .get_thunk(selected)
        .expect("inherited select is a heap-owned thunk");
    assert!(selected_thunk.env().is_none());
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_attrs_allocation_dispatch_skips_synthetic_select_thunk_fields() {
    let ir = lower("{ inherit ({ a = 1; }) a; }");
    let a = symbol_for(&ir, b"a");
    let default_outcome = eval_whnf_owned(&ir).expect("default inherited attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress inherited attrset evaluates without synthetic select writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let selected = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(selected.tag(), ValueTag::Thunk);
    let selected_thunk = outcome
        .heap()
        .get_thunk(selected)
        .expect("inherited select is a heap-owned thunk");
    assert!(matches!(
        selected_thunk.kind(),
        EvalThunkKind::Select { .. }
    ));
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
        .expect("root attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_thunk_allocation_dispatch_skips_application_argument_locals() {
    let ir = lower("(x: 1) (y: y)");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress root application evaluates without hidden callee-local writebacks");

    assert_eq!(outcome.value().as_int(), Ok(1));
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), 1);
    assert_eq!(
        outcome
            .heap()
            .generation(thunk_values[0])
            .expect("argument thunk source generation is known"),
        HeapGeneration::Young
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("argument thunk allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_thunk_allocation_dispatch_skips_synthetic_apply_accumulators() {
    let ir = lower("builtins.map (x: x) [ 1 2 ]");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress map evaluates without synthetic apply accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::List);
    let elements = {
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("mapped list is heap-owned");
        assert_eq!(list.len(), 2);
        [
            list.get(0).expect("first mapped element exists"),
            list.get(1).expect("second mapped element exists"),
        ]
    };
    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), elements.len());
    for element in elements {
        assert_eq!(element.tag(), ValueTag::Thunk);
        assert!(thunk_values.iter().any(|value| value.raw_eq(element)));
        let thunk = outcome
            .heap()
            .get_thunk(element)
            .expect("mapped element is a heap-owned thunk");
        assert!(matches!(thunk.kind(), EvalThunkKind::Apply { .. }));
    }
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn gc_stress_attrs_allocation_dispatch_skips_direct_eval_node_callers() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let value = evaluator
        .eval_node(ir.root)
        .expect("direct attrset node evaluation succeeds");

    assert_eq!(value.tag(), ValueTag::Attrs);
    let attr_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    assert_eq!(attr_value.tag(), ValueTag::Thunk);
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(thunk_values.len(), 1);
    assert_eq!(
        thunk_values
            .iter()
            .filter(|value| value.raw_eq(attr_value))
            .count(),
        1
    );
    assert!(evaluator.heap().allocation_safepoints().count() >= 1);
    let final_worker_safepoint = evaluator
        .heap()
        .allocation_safepoints()
        .last()
        .expect("direct attrset worker allocation safepoint records");
    assert_eq!(
        final_worker_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        final_worker_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("direct attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn heap_cheap_memory_advice_option_can_be_configured() {
    let mut options = TreeWalkOptions::new();

    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), None);
    options.set_heap_cheap_memory_advice_min_idle_epochs(7);
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), Some(7));
    options.clear_heap_cheap_memory_advice();
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), None);

    let options = TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(3);
    assert_eq!(options.heap_cheap_memory_advice_min_idle_epochs(), Some(3));
}

#[test]
fn heap_cheap_memory_advice_option_reports_after_tree_walk_eval() {
    let ir = lower("\"advised\"");
    let default_outcome = eval_whnf_owned(&ir).expect("string evaluates without advice");
    assert_eq!(default_outcome.cheap_memory_advice_report(), None);
    assert_eq!(default_outcome.cheap_memory_budget_plan(), None);

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(0),
    )
    .expect("string evaluates");

    assert_eq!(outcome.stats(), default_outcome.stats());
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("advised result is a heap-owned string")
            .bytes(),
        default_outcome
            .heap()
            .get_string(default_outcome.value())
            .expect("default result is a heap-owned string")
            .bytes()
    );
    let report = outcome
        .cheap_memory_advice_report()
        .expect("cheap heap advice report is recorded");
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert!(report.cold_hash_consed().records() >= 1);
    assert!(report.cold_hash_consed().requested_bytes() > 0);
    assert_eq!(outcome.heap().memory_budget_poll_count(), 0);
    assert_eq!(outcome.heap().last_memory_budget_action(), None);
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn heap_cheap_memory_advice_option_reports_after_attr_path_eval() {
    let ir = lower("{ selected = \"advised\"; }");
    let attr_path = vec![b"selected".to_vec()];
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &attr_path,
        TreeWalkOptions::with_heap_cheap_memory_advice_min_idle_epochs(0),
        None,
    )
    .expect("attr-path evaluation succeeds");

    let report = outcome
        .cheap_memory_advice_report()
        .expect("attr-path outcomes also carry the post-evaluation advice report");
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert_eq!(outcome.heap().memory_budget_poll_count(), 0);
    assert_eq!(outcome.heap().last_memory_budget_action(), None);
    assert_eq!(outcome.cheap_memory_budget_plan(), None);
}

#[test]
fn heap_budget_and_cheap_advice_options_report_cold_aware_plan() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let ir = lower("\"planned\"");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("string evaluates");

    let action = outcome
        .memory_budget_action()
        .expect("heap budget still records the automatic action");
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().sample().cold_hash_consed_bytes(),
        0,
        "automatic allocation polling stays on unused-tail action telemetry"
    );
    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("combined options record a cold-aware budget plan");
    assert_eq!(plan.decision().budget(), budget);
    assert!(
        plan.decision().sample().cold_hash_consed_bytes() > 0,
        "the opt-in plan carries cold hash-consed spill capacity"
    );
    let plan_report = plan
        .cheap_advice_report()
        .expect("over-budget cold-aware planning records advice telemetry");
    assert_eq!(outcome.cheap_memory_advice_report(), Some(plan_report));
    assert_eq!(outcome.cold_hash_consed_value_materialization(), None);
    assert_eq!(plan_report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(
        plan_report.cold_hash_consed().kind(),
        MemoryAdviceKind::Evict
    );
    assert_eq!(plan_report.cold_hash_consed().min_idle_epochs(), 0);
}

#[test]
fn heap_budget_and_persistent_cache_materialize_cold_values_after_reclaim_plan() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let persist_root = unique_temp_dir("heap-budget-cold-value-materialization");
    let ir = lower("\"spill-prep\"");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);
    options.set_persist_cache_root(&persist_root);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("string evaluates");

    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("combined options record a cold-aware budget plan");
    assert!(
        plan.cheap_advice_report().is_some(),
        "the tiny budget should request reclaim"
    );
    let materialization = outcome
        .cold_hash_consed_value_materialization()
        .expect("persistent cache root enables cold value materialization");
    assert!(materialization.candidates() >= 1);
    assert_eq!(materialization.captured(), materialization.candidates());
    assert_eq!(materialization.uncapturable(), 0);
    assert_eq!(materialization.errors(), 0);
    assert_eq!(materialization.cache_unavailable(), 0);
    assert_eq!(
        materialization.materialized_hashes().len(),
        materialization.materialized()
    );
    assert!(
        !materialization.materialized_hashes().is_empty(),
        "the outcome report should name the ensured indexed value payloads"
    );

    let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
    for value_hash in materialization.materialized_hashes() {
        let payload = persist_cache
            .load_cached_expression_value_indexed(*value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists");
        assert_eq!(payload.value_hash().expect("payload hashes"), *value_hash);
    }

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn attr_path_heap_budget_and_persistent_cache_materialize_cold_values_after_reclaim_plan() {
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    let persist_root = unique_temp_dir("attr-path-heap-budget-cold-value-materialization");
    let ir = lower("{ selected = \"spill-prep-attr\"; }");
    let attr_path = vec![b"selected".to_vec()];
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);
    options.set_persist_cache_root(&persist_root);

    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir, &attr_path, options, None,
    )
    .expect("attr-path selection evaluates");
    assert_eq!(
        outcome
            .heap()
            .get_string(outcome.value())
            .expect("selected value is a heap-owned string")
            .bytes(),
        b"spill-prep-attr"
    );

    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("attr-path outcome records a cold-aware budget plan");
    assert!(
        plan.cheap_advice_report().is_some(),
        "the tiny budget should request reclaim"
    );
    let materialization = outcome
        .cold_hash_consed_value_materialization()
        .expect("attr-path outcome runs cold value materialization");
    assert!(materialization.candidates() >= 1);
    assert_eq!(materialization.captured(), materialization.candidates());
    assert_eq!(materialization.uncapturable(), 0);
    assert_eq!(materialization.errors(), 0);
    assert_eq!(materialization.cache_unavailable(), 0);
    assert_eq!(
        materialization.materialized_hashes().len(),
        materialization.materialized()
    );
    assert!(
        !materialization.materialized_hashes().is_empty(),
        "the attr-path report should name the ensured indexed value payloads"
    );

    let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
    for value_hash in materialization.materialized_hashes() {
        let payload = persist_cache
            .load_cached_expression_value_indexed(*value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists");
        assert_eq!(payload.value_hash().expect("payload hashes"), *value_hash);
    }

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}

#[test]
fn heap_budget_and_cheap_advice_options_fall_back_to_cold_advice_under_soft_limit() {
    let budget = HeapMemoryBudget::new(usize::MAX).expect("budget is non-zero");
    let ir = lower("\"under-budget\"");
    let mut options = TreeWalkOptions::with_heap_memory_budget(budget);
    options.set_heap_cheap_memory_advice_min_idle_epochs(0);

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("string evaluates");

    let plan = outcome
        .cheap_memory_budget_plan()
        .expect("combined options record a cold-aware budget plan");
    assert!(matches!(
        plan.decision().response(),
        HeapMemoryBudgetResponse::ContinueTierA { .. }
    ));
    assert_eq!(plan.cheap_advice_report(), None);
    let report = outcome
        .cheap_memory_advice_report()
        .expect("under-budget combined options still record plain advice telemetry");
    assert_eq!(outcome.cold_hash_consed_value_materialization(), None);
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
}

#[test]
fn force_cache_materialization_costs_can_be_configured() {
    let costs = MaterializationCosts::new(20, 3, 4, 5);
    let mut options = TreeWalkOptions::new();

    assert_eq!(
        options.force_cache_materialization_costs(),
        MaterializationCosts::new(4, 1, 1, 1)
    );
    options.set_force_cache_materialization_costs(costs);
    assert_eq!(options.force_cache_materialization_costs(), costs);

    let options = TreeWalkOptions::with_force_cache_materialization_costs(costs);
    assert_eq!(options.force_cache_materialization_costs(), costs);
}

#[test]
fn unary_type_predicate_primops_classify_whnf_values() {
    assert_eq!(eval("builtins.isAttrs { a = 1; }").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isAttrs [ 1 ]").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isList [ 1 ]").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFunction (x: x)").as_bool(), Ok(true));
    assert_eq!(
        eval("builtins.isFunction builtins.length").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("builtins.isFunction (builtins.map (x: x))").as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isString \"x\"").as_bool(), Ok(true));
    let ir = lower("builtins.isString \"x\"");
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
        .expect("isString argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"x".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");
    assert_eq!(
        evaluator
            .eval_strict_unary_primop_value(
                ir.root,
                root.span,
                StrictUnaryPrimOp::IsString,
                argument,
                argument_span,
                value,
            )
            .expect("isString evaluates context-bearing strings")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(eval("builtins.isInt 1").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isInt 1.0").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isFloat 1.0").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isFloat 1").as_bool(), Ok(false));
    assert_eq!(eval("builtins.isBool false").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isNull null").as_bool(), Ok(true));
    assert_eq!(eval("isNull null").as_bool(), Ok(true));
    assert_eq!(
        eval("let isNull = x: false; in isNull null").as_bool(),
        Ok(false)
    );
    assert_eq!(eval("builtins.isPath /tmp").as_bool(), Ok(true));
    assert_eq!(eval("builtins.isPath \"not-path\"").as_bool(), Ok(false));
}

#[test]
fn type_of_primop_returns_nix_type_names() {
    assert_eq!(eval_string_bytes("builtins.typeOf 1"), b"int");
    assert_eq!(eval_string_bytes("builtins.typeOf 1.0"), b"float");
    assert_eq!(eval_string_bytes("builtins.typeOf false"), b"bool");
    assert_eq!(eval_string_bytes("builtins.typeOf null"), b"null");
    assert_eq!(eval_string_bytes("builtins.typeOf \"x\""), b"string");
    assert_eq!(eval_string_bytes("builtins.typeOf /tmp"), b"path");
    assert_eq!(eval_string_bytes("builtins.typeOf [ 1 ]"), b"list");
    assert_eq!(eval_string_bytes("builtins.typeOf { a = 1; }"), b"set");
    assert_eq!(eval_string_bytes("builtins.typeOf (x: x)"), b"lambda");
    assert_eq!(
        eval_string_bytes("builtins.typeOf builtins.length"),
        b"lambda"
    );
    assert_eq!(
        eval_string_bytes("builtins.typeOf (builtins.map (x: x))"),
        b"lambda"
    );
}

#[test]
fn builtin_lookup_uses_shared_declaration_registry() {
    let builtin_names = BUILTINS.iter().map(Builtin::name).collect::<BTreeSet<_>>();

    assert_eq!(builtin_names.len(), BUILTINS.len());
    for builtin in BUILTINS.iter().copied() {
        assert_eq!(lookup_builtin(builtin.name()), Some(builtin));
    }
}

#[test]
fn direct_builtin_arity_uses_direct_metadata_not_first_class_metadata() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"__testBuiltin").expect("symbol interns");
    let call = BuiltinCall::new(IrId::new(0), Span::new(0, 13), symbol);
    let builtin = Builtin::test_with_call_arities(
        Some(BuiltinDirect::LazyUnary {
            effect: BuiltinEffect::Pure,
        }),
        Some(3),
    );

    check_builtin_direct_arity(call, builtin, 1).expect("direct arity uses direct metadata");

    let error = check_builtin_direct_arity(call, builtin, 3)
        .expect_err("direct arity ignores first-class arity");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::InvalidPrimOpArity {
            id: call.id,
            symbol: call.symbol,
            expected: 1,
            actual: 3,
        }
    );
}

#[test]
fn builtin_surface_matches_pinned_flakes_golden_fixture() {
    let fixture = pinned_builtin_name_bytes();
    assert_eq!(fixture.len(), BUILTINS.len());
    assert!(fixture.windows(2).all(|pair| pair[0] < pair[1]));

    let registry_names = BUILTINS
        .iter()
        .map(|builtin| builtin.name().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(registry_names, fixture);

    let mut options =
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec()).expect("system valid");
    options.set_current_time(1_700_000_000).expect("time valid");

    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins", options.clone()),
        fixture,
    );
    assert_eq!(
        eval_list_string_bytes_with_options("builtins.attrNames builtins.builtins", options),
        fixture,
    );
}

#[test]
fn version_gated_builtin_names_match_pinned_flakes_surface() {
    for name in VERSION_GATED_BUILTIN_NAMES {
        let fixture_contains = PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES.contains(name);
        let registry_contains = BUILTINS.lookup(name.as_bytes()).is_some();
        assert_eq!(
            registry_contains, fixture_contains,
            "{name} local registration should match the pinned flake-enabled fixture",
        );

        let source = format!("builtins.hasAttr {} builtins", nix_string_literal(name));
        assert_eq!(
            eval(&source).as_bool(),
            Ok(fixture_contains),
            "{name} runtime presence should match the pinned flake-enabled fixture",
        );
    }
}

#[test]
fn custom_effectful_unary_builtin_declarations_match_runtime_impls() {
    for name in [
        b"pathExists".as_slice(),
        b"readDir".as_slice(),
        b"readFile".as_slice(),
        b"readFileType".as_slice(),
        b"storePath".as_slice(),
    ] {
        assert_eq!(
            direct_builtin(name),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        let builtin = lookup_builtin(name).expect("builtin is registered");

        assert_eq!(builtin.first_class_arity(), Some(1));
        assert!(!builtin.docs().summary().is_empty());
    }
}

#[test]
fn tree_walk_options_normalize_store_dir() {
    let defaulted = TreeWalkOptions::with_store_dir(Vec::new()).expect("empty store dir defaults");
    assert_eq!(defaulted.store_dir(), b"/nix/store");

    let normalized = TreeWalkOptions::with_store_dir(b"//tmp//aos-store/./".to_vec())
        .expect("absolute store dir normalizes");
    assert_eq!(normalized.store_dir(), b"/tmp/aos-store");

    let parent_normalized = TreeWalkOptions::with_store_dir(b"/tmp/../aos-store".to_vec())
        .expect("parent components reduce");
    assert_eq!(parent_normalized.store_dir(), b"/aos-store");

    let nested_parent_normalized =
        TreeWalkOptions::with_store_dir(b"/tmp/aos-store/../other".to_vec())
            .expect("nested parent components reduce");
    assert_eq!(nested_parent_normalized.store_dir(), b"/tmp/other");

    let mut options = TreeWalkOptions::new();
    options
        .set_store_dir(b"/var//aos/store//".to_vec())
        .expect("absolute store dir sets");
    assert_eq!(options.store_dir(), b"/var/aos/store");

    assert_eq!(
        TreeWalkOptions::with_store_dir(b"relative/store".to_vec())
            .expect_err("relative store dir is rejected"),
        TreeWalkOptionsError::RelativeStoreDir
    );

    let base = TreeWalkOptions::with_search_path_base(b"//tmp//aos-search/./".to_vec())
        .expect("absolute search-path base normalizes");
    assert_eq!(base.search_path_base(), b"/tmp/aos-search");

    let mut options = TreeWalkOptions::new();
    options
        .set_search_path_base(b"/var//aos/search//".to_vec())
        .expect("absolute search-path base sets");
    assert_eq!(options.search_path_base(), b"/var/aos/search");

    assert_eq!(
        TreeWalkOptions::with_search_path_base(b"relative/search".to_vec())
            .expect_err("relative search-path base is rejected"),
        TreeWalkOptionsError::RelativeSearchPathBase
    );

    let path_base = TreeWalkOptions::with_path_literal_base(b"//tmp//aos-source/./".to_vec())
        .expect("absolute path-literal base normalizes");
    assert_eq!(
        path_base.path_literal_base(),
        Some(b"/tmp/aos-source".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.path_literal_base(), None);
    options
        .set_path_literal_base(b"/var//aos/source//".to_vec())
        .expect("absolute path-literal base sets");
    assert_eq!(
        options.path_literal_base(),
        Some(b"/var/aos/source".as_slice())
    );
    options.clear_path_literal_base();
    assert_eq!(options.path_literal_base(), None);

    assert_eq!(
        TreeWalkOptions::with_path_literal_base(b"relative/source".to_vec())
            .expect_err("relative path-literal base is rejected"),
        TreeWalkOptionsError::RelativePathLiteralBase
    );

    let home_dir = TreeWalkOptions::with_home_dir(b"//tmp//aos-home/./".to_vec())
        .expect("absolute home directory normalizes");
    assert_eq!(home_dir.home_dir(), Some(b"/tmp/aos-home".as_slice()));

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.home_dir(), None);
    options
        .set_home_dir(b"/var//aos/home//".to_vec())
        .expect("absolute home directory sets");
    assert_eq!(options.home_dir(), Some(b"/var/aos/home".as_slice()));
    options.clear_home_dir();
    assert_eq!(options.home_dir(), None);

    assert_eq!(
        TreeWalkOptions::with_home_dir(b"relative/home".to_vec())
            .expect_err("relative home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
    assert_eq!(
        TreeWalkOptions::with_home_dir(Vec::new()).expect_err("empty home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
}

#[test]
fn to_file_uses_configured_store_dir() {
    let options = TreeWalkOptions::with_store_dir(b"/custom/store".to_vec())
        .expect("custom store dir configures");
    let path = eval_string_bytes_with_options(r#"builtins.toFile "x" "abc""#, options);

    assert!(path.starts_with(b"/custom/store/"), "{path:?}");
    assert!(path.ends_with(b"-x"), "{path:?}");
}

#[test]
fn tree_walk_options_configure_current_system() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_system(), None);

    let configured = TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem configures");
    assert_eq!(
        configured.current_system(),
        Some(b"aarch64-linux".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem sets");
    assert_eq!(options.current_system(), Some(b"x86_64-linux".as_slice()));
    options.clear_current_system();
    assert_eq!(options.current_system(), None);

    assert_eq!(
        TreeWalkOptions::with_current_system(Vec::new())
            .expect_err("empty currentSystem is rejected"),
        TreeWalkOptionsError::EmptyCurrentSystem
    );
}

#[test]
fn tree_walk_options_configure_current_time() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_time(), None);

    let configured =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime configures");
    assert_eq!(configured.current_time(), Some(1_700_000_000));

    let mut options = TreeWalkOptions::new();
    options
        .set_current_time(1_700_000_001)
        .expect("currentTime sets");
    assert_eq!(options.current_time(), Some(1_700_000_001));
    options.clear_current_time();
    assert_eq!(options.current_time(), None);

    assert_eq!(
        TreeWalkOptions::with_current_time(-1).expect_err("negative currentTime is rejected"),
        TreeWalkOptionsError::NegativeCurrentTime
    );
}

#[test]
fn tree_walk_options_configure_trace_verbose() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.trace_verbose());

    let configured = TreeWalkOptions::with_trace_verbose(true);
    assert!(configured.trace_verbose());

    let mut options = TreeWalkOptions::new();
    options.set_trace_verbose(true);
    assert!(options.trace_verbose());
    options.set_trace_verbose(false);
    assert!(!options.trace_verbose());
}

#[test]
fn tree_walk_options_configure_abort_on_warn() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.abort_on_warn());

    let configured = TreeWalkOptions::with_abort_on_warn(true);
    assert!(configured.abort_on_warn());

    let mut options = TreeWalkOptions::new();
    options.set_abort_on_warn(true);
    assert!(options.abort_on_warn());
    options.set_abort_on_warn(false);
    assert!(!options.abort_on_warn());
}

#[test]
fn tree_walk_options_configure_max_call_depth() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.max_call_depth(), DEFAULT_MAX_CALL_DEPTH);

    let configured = TreeWalkOptions::with_max_call_depth(10);
    assert_eq!(configured.max_call_depth(), 10);

    let mut options = TreeWalkOptions::new();
    options.set_max_call_depth(0);
    assert_eq!(options.max_call_depth(), 0);
}

#[test]
fn tree_walk_options_configure_filesystem_access_policy() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.eval_mode(), EvalMode::Impure);
    assert!(defaulted.allowed_paths().is_empty());
    assert!(defaulted.allowed_uris().is_empty());

    let restricted = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    assert_eq!(restricted.eval_mode(), EvalMode::Restricted);

    let mut options = TreeWalkOptions::new();
    options.set_eval_mode(EvalMode::Pure);
    assert_eq!(options.eval_mode(), EvalMode::Pure);
    options
        .add_allowed_path(b"/tmp//allowed/./".to_vec())
        .expect("absolute allowed path configures");
    assert_eq!(options.allowed_paths(), &[b"/tmp/allowed".to_vec()]);
    options
        .set_allowed_paths(vec![b"/var/../tmp/other".to_vec()])
        .expect("allowed paths replace");
    assert_eq!(options.allowed_paths(), &[b"/tmp/other".to_vec()]);
    options.clear_allowed_paths();
    assert!(options.allowed_paths().is_empty());

    options
        .add_allowed_uri(b"https://cache.example/".to_vec())
        .expect("allowed URI prefix configures");
    assert_eq!(
        options.allowed_uris(),
        &[b"https://cache.example/".to_vec()]
    );
    assert!(options.uri_is_allowed(b"https://cache.example/source.tar.gz"));
    assert!(!options.uri_is_allowed(b"https://other.example/source.tar.gz"));
    options
        .set_allowed_uris(vec![b"github:".to_vec()])
        .expect("allowed URI prefixes replace");
    assert_eq!(options.allowed_uris(), &[b"github:".to_vec()]);
    options.clear_allowed_uris();
    assert!(options.allowed_uris().is_empty());

    assert_eq!(
        options
            .add_allowed_path(b"relative/path".to_vec())
            .expect_err("relative allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_path(Vec::new())
            .expect_err("empty allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_uri(Vec::new())
            .expect_err("empty allowed URI prefixes are rejected"),
        TreeWalkOptionsError::EmptyAllowedUri
    );
}

#[test]
fn tree_walk_options_configure_environment_variables() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.env_var(b"HOME"), None);

    let configured = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/homeless".to_vec());
    assert_eq!(configured.env_var(b"HOME"), Some(b"/homeless".as_slice()));
    assert_eq!(configured.env_var(b"USER"), None);

    let mut options = TreeWalkOptions::new();
    options.set_env_var(b"USER".to_vec(), b"builder".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"builder".as_slice()));
    options.set_env_var(b"USER".to_vec(), b"overridden".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"overridden".as_slice()));
    options.clear_env_var(b"USER");
    assert_eq!(options.env_var(b"USER"), None);
}

#[test]
fn tree_walk_options_configure_ambient_search_path_rejection() {
    let mut options = TreeWalkOptions::new();
    assert!(!options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(true);
    assert!(options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(false);
    assert!(!options.reject_ambient_search_path());
}
