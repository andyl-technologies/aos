//! Tree-walk evaluator tests: options.

// Many GC-stress tests here are gated off under the Candidate-C variant
// (record placement outside the single reservation), leaving shared helpers
// unused on that carrier only; the baseline still uses them.
#![cfg_attr(feature = "candidate_c_value", allow(dead_code))]

use super::*;
use crate::attrs::repr::AttrSetReprKind;
use crate::eval::heap::EvalThunkForceStorageMode;
use serde_json::Number as JsonNumber;
use crate::eval::heap::{
    EvalHeap, EvalHeapMemoryBudgetAction, EvalHeapResidentMemoryMode, EvalHeapResidentMemorySource,
};
use crate::eval::{
    EvalThunk, ForceError, ParallelThunkTerminalStatus, ParallelThunkWorkerId,
    TreeWalkParallelThunkWait,
};
use crate::heap::{GcHeapAddress, HeapGeneration, HeapMemoryBudgetResponse, MemoryAdviceKind};
use crate::runtime::alloc::{
    AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint, RuntimeAllocator,
};

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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_alloc_symbol_string_helper_dispatches_permanent_noop_bridge() {
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

    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_symbol_string(ir.root, span, symbol)
        })
        .expect("symbol helper string allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating symbol helper string"
    );
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
    assert_eq!(evaluator.heap().len(), 3);
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[RuntimeAllocationEntryPoint::AosAllocString],
        "symbol string helper should dispatch exactly one permanent string allocation"
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_find_file_path_helper_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
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
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_find_file_path(ir.root, span, b"/tmp/gc-stress-find-file".to_vec())
        })
        .expect("findFile path helper allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating findFile path"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Path);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("findFile path generation is known"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        evaluator
            .heap()
            .get_path(value)
            .expect("findFile path is heap-owned")
            .bytes(),
        b"/tmp/gc-stress-find-file"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        1
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[RuntimeAllocationEntryPoint::AosAllocString],
        "findFile path helper should dispatch exactly one permanent path allocation"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("findFile path allocation safepoint records");
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

fn assert_gc_stress_root_string_result_dispatches(source: &str, expected: &[u8]) {
    assert_gc_stress_root_string_result_dispatches_with_options(
        source,
        expected,
        TreeWalkOptions::new(),
    );
}

fn assert_gc_stress_root_string_result_dispatches_with_options(
    source: &str,
    expected: &[u8],
    mut options: TreeWalkOptions,
) {
    let ir = lower(source);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    options.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let mut evaluator = TreeWalk::with_options(&ir, options);
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

fn assert_gc_stress_root_string_result_skips_dispatch(source: &str, expected: &[u8]) {
    assert_gc_stress_root_string_result_skips_dispatch_with_options(
        source,
        expected,
        TreeWalkOptions::new(),
    );
}

fn assert_gc_stress_root_string_result_skips_dispatch_with_options(
    source: &str,
    expected: &[u8],
    mut options: TreeWalkOptions,
) {
    let ir = lower(source);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    options.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let mut evaluator = TreeWalk::with_options(&ir, options);
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
        roots[0].raw_eq(local_source),
        "registered root relocated while evaluating {source}"
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
    assert!(evaluator.heap().permanent_allocation_safepoints().count() > 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("permanent allocation safepoint records");
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

fn assert_gc_stress_root_bool_result_skips_dispatch(source: &str, expected: bool) {
    assert_gc_stress_root_bool_result_skips_dispatch_with_options(
        source,
        expected,
        TreeWalkOptions::new(),
    );
}

fn assert_gc_stress_root_bool_result_skips_dispatch_with_options(
    source: &str,
    expected: bool,
    mut options: TreeWalkOptions,
) {
    let ir = lower(source);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    options.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let mut evaluator = TreeWalk::with_options(&ir, options);
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
        roots[0].raw_eq(local_source),
        "registered root relocated while evaluating {source}"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.as_bool(), Ok(expected));
    assert!(evaluator.heap().permanent_allocation_safepoints().count() > 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("permanent allocation safepoint records");
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

fn assert_gc_stress_root_path_result_dispatches(
    source: &str,
    expected: &[u8],
    expected_allocation_shape: Option<(u64, &[RuntimeAllocationEntryPoint])>,
) {
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

    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
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
    if let Some((expected_safepoints, expected_dispatches)) = expected_allocation_shape {
        assert_eq!(
            evaluator.heap().permanent_allocation_safepoints().count(),
            permanent_safepoints_before + expected_safepoints,
            "root path helper evaluation recorded an unexpected permanent safepoint count for {source}"
        );
        assert_eq!(
            &evaluator.gc_stress_permanent_root_allocation_dispatches()
                [permanent_dispatches_before..],
            expected_dispatches,
            "root path helper recorded an unexpected permanent dispatch suffix for {source}"
        );
    }
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_unary_path_result_helpers_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_path_result_dispatches(
        "builtins.dirOf /tmp/gc-stress-root-name",
        b"/tmp",
        Some((2, &[RuntimeAllocationEntryPoint::AosAllocString])),
    );
    assert_gc_stress_root_path_result_dispatches(
        r#"/tmp/${"gc-stress-interpolated-path"}"#,
        b"/tmp/gc-stress-interpolated-path",
        Some((2, &[RuntimeAllocationEntryPoint::AosAllocString])),
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_split_version_empty_list_result_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let input = evaluator
        .heap
        .alloc_string(NixString::from_bytes(Vec::new()))
        .expect("splitVersion input string allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_split_version_primop(ir.root, span, ir.root, span, input)
        })
        .expect("splitVersion empty list allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "splitVersion result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating splitVersion empty list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("splitVersion list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("splitVersion result is heap-owned");
    assert!(list.is_empty());
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("splitVersion list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_split_version_segment_strings_and_result_list_dispatch() {
    let ir = lower(r#"builtins.splitVersion "1.0pre2""#);
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
        .expect("splitVersion argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let input = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"1.0pre2".to_vec()))
        .expect("splitVersion input string allocates");
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
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, root.span, &mut roots, |eval| {
            eval.eval_split_version_primop(ir.root, root.span, argument, argument_span, input)
        })
        .expect("splitVersion non-empty list allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "splitVersion result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating splitVersion segment strings"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("splitVersion list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("splitVersion result is heap-owned");
    let expected: &[&[u8]] = &[b"1", b"0", b"pre", b"2"];
    assert_eq!(list.len(), expected.len());
    for (index, expected) in expected.iter().enumerate() {
        let element = list.get(index).expect("splitVersion element exists");
        assert_eq!(
            evaluator
                .heap()
                .get_string(element)
                .expect("splitVersion segment string is heap-owned")
                .bytes(),
            *expected
        );
    }
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocList,
        ],
        "splitVersion should dispatch segment strings before the final list"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 5,
        "splitVersion should allocate exactly four segment strings and the final list under GC stress"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("splitVersion list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_match_capture_list_result_dispatches_permanent_noop_bridge() {
    let ir = lower(r#"builtins.match "(a)(b)" "ab""#);
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

    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("match capture list evaluates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "match capture list did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating match capture list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    let captures = evaluator
        .heap()
        .get_list(value)
        .expect("match captures are heap-owned");
    assert_eq!(captures.len(), 2);
    assert_eq!(
        evaluator
            .heap()
            .get_string(captures.get(0).expect("first capture exists"))
            .expect("first capture is a string")
            .bytes(),
        b"a"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_string(captures.get(1).expect("second capture exists"))
            .expect("second capture is a string")
            .bytes(),
        b"b"
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocList,
        ],
        "match should dispatch capture strings before the final capture list"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("match capture list safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_split_capture_and_result_lists_preserve_accumulated_values() {
    let ir = lower(r#"builtins.split "([-=])" "a-b=c""#);
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

    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("split result evaluates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 3,
        "split capture lists and result list did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating split regex lists"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    let items = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("split result is heap-owned");
        assert_eq!(list.len(), 5);
        [
            list.get(0).expect("first split item exists"),
            list.get(1).expect("second split item exists"),
            list.get(2).expect("third split item exists"),
            list.get(3).expect("fourth split item exists"),
            list.get(4).expect("fifth split item exists"),
        ]
    };
    assert_heap_string_bytes(&evaluator, items[0], b"a");
    assert_heap_string_bytes(&evaluator, items[2], b"b");
    assert_heap_string_bytes(&evaluator, items[4], b"c");
    for (capture_list, expected) in [(items[1], b"-".as_slice()), (items[3], b"=".as_slice())] {
        let captures = evaluator
            .heap()
            .get_list(capture_list)
            .expect("split capture list is heap-owned");
        assert_eq!(captures.len(), 1);
        assert_heap_string_bytes(
            &evaluator,
            captures.get(0).expect("split capture exists"),
            expected,
        );
    }
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocList,
        ],
        "split should dispatch the first text string, capture string, and capture list before accumulated capture-list roots block later dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("split result list safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nix_path_value_result_list_preserves_accumulated_entries() {
    let ir = lower("builtins.nixPath");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options
        .add_nix_path_entry(b"left".to_vec(), b"/aos/left".to_vec())
        .expect("left nixPath entry configures");
    options
        .add_nix_path_entry(b"right".to_vec(), b"/aos/right".to_vec())
        .expect("right nixPath entry configures");
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("nixPath value evaluates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "nixPath result list did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating nixPath result list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    let items = {
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("nixPath result is heap-owned");
        assert_eq!(list.len(), 2);
        [
            list.get(0).expect("first nixPath entry exists"),
            list.get(1).expect("second nixPath entry exists"),
        ]
    };
    assert_nix_path_entry(&mut evaluator, items[0], b"left", b"/aos/left");
    assert_nix_path_entry(&mut evaluator, items[1], b"right", b"/aos/right");
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "nixPath should dispatch the first entry path/prefix strings before accumulated entry roots block later generated allocations"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 7,
        "nixPath should allocate four strings, two generated entry attrsets, and the final list under GC stress"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("nixPath result list safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_reflected_context_outputs_list_preserves_accumulated_outputs() {
    let ir = lower("\"root\"");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let mut group =
        ReflectedContextGroup::new(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv".to_vec());
    group.outputs = vec![b"out".to_vec(), b"dev".to_vec()];
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_reflected_context_group(ir.root, span, group)
        })
        .expect("reflected context group allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "reflected context outputs list did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating reflected context outputs list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let outputs_key = evaluator
        .symbols
        .intern(b"outputs")
        .expect("outputs key interns");
    let outputs = {
        let group_attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("context group is an attrset");
        assert_eq!(group_attrs.len(), 1);
        group_attrs.get(outputs_key).expect("outputs attr exists")
    };
    let output_items = {
        let outputs = evaluator
            .heap()
            .get_list(outputs)
            .expect("outputs value is a heap-owned list");
        assert_eq!(outputs.len(), 2);
        [
            outputs.get(0).expect("first output exists"),
            outputs.get(1).expect("second output exists"),
        ]
    };
    assert_heap_string_bytes(&evaluator, output_items[0], b"out");
    assert_heap_string_bytes(&evaluator, output_items[1], b"dev");
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocList,
        ],
        "reflected context should dispatch output-name strings and the outputs list but not the final generated attrset"
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 4,
        "reflected context should allocate exactly two output strings, the outputs list, and the final attrset under GC stress"
    );
    let final_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("reflected context final attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_substring_string_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(r#"builtins.substring 1 2 "abcd""#, b"bc");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_add_operator_scalar_results_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(r#""a" + "b""#, b"ab");
    assert_gc_stress_root_path_result_dispatches(
        r#"/tmp/gc-stress-root + "/name""#,
        b"/tmp/gc-stress-root/name",
        None,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_to_string_scalar_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches("builtins.toString 123", b"123");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_store_path_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(
        r#"builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src""#,
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_to_file_result_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches(
        r#"builtins.toFile "foo" "bar""#,
        b"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_to_file_result_skips_unregistered_outer_locals() {
    assert_gc_stress_root_bool_result_skips_dispatch(
        r#""left" == builtins.toFile "foo" "bar""#,
        false,
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_interpolation_literal_result_dispatch_permanent_noop_bridge() {
    let root = IrId::new(0);
    let span = Span::new(0, 2);
    let ir = manual_ir(root, vec![pure_node(IrKind::Interp, span, IrData::None)]);
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
        .expect("GC-stress interpolation expression evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while evaluating manual empty interpolation"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .get_string(value)
            .expect("interpolation result is heap-owned")
            .bytes(),
        b""
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root interpolation allocation safepoint records");
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
fn gc_stress_nested_path_interpolation_coercion_skips_unregistered_outer_locals() {
    let (dir, path) = temp_file_with_bytes("gc-stress-path-interpolation", b"abc");
    let path = path_source(&path);
    assert_gc_stress_root_bool_result_skips_dispatch(&format!(r#""left" == "${{{path}}}""#), false);
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_path_source_string_results_skip_interned_source_setup() {
    let (file_dir, file_path) = temp_file_with_bytes("gc-stress-source-path", b"abc");
    let file_path = path_source(&file_path);
    let source = format!("builtins.path {{ path = {file_path}; }}");
    let expected = eval_string_bytes(&source);
    assert_gc_stress_root_string_result_skips_dispatch(&source, &expected);
    fs::remove_dir_all(file_dir).expect("temp directory removes");

    let dir = unique_temp_dir("gc-stress-source-path-filter");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("source tree creates");
    fs::write(tree.join("a"), b"one").expect("included source file writes");
    fs::write(tree.join("b"), b"two").expect("excluded source file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.baseNameOf path == "a""#;
    let source = format!("builtins.path {{ path = {tree}; filter = ({keep}); }}");
    let expected = eval_string_bytes(&source);
    assert_gc_stress_root_string_result_skips_dispatch(&source, &expected);
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_filter_source_string_result_dispatch_permanent_noop_bridge() {
    let dir = unique_temp_dir("gc-stress-filter-source");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("source tree creates");
    fs::write(tree.join("a"), b"one").expect("included source file writes");
    fs::write(tree.join("b"), b"two").expect("excluded source file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.baseNameOf path == "a""#;
    let source = format!("builtins.filterSource ({keep}) {tree}");
    let expected = eval_string_bytes(&source);
    assert_gc_stress_root_string_result_dispatches(&source, &expected);
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_source_path_string_results_skip_unregistered_outer_locals() {
    let (file_dir, file_path) = temp_file_with_bytes("gc-stress-nested-source-path", b"abc");
    let file_path = path_source(&file_path);
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.path {{ path = {file_path}; }}"#),
        false,
    );
    fs::remove_dir_all(file_dir).expect("temp directory removes");

    let dir = unique_temp_dir("gc-stress-nested-filter-source");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("source tree creates");
    fs::write(tree.join("a"), b"one").expect("included source file writes");
    fs::write(tree.join("b"), b"two").expect("excluded source file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.baseNameOf path == "a""#;
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.filterSource ({keep}) {tree}"#),
        false,
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

const GC_STRESS_FETCH_TARBALL_DIGEST: &str =
    "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

fn nix_sha256_digest_from_hex(hex: &str) -> NixSha256Digest {
    let bytes = hex.as_bytes();
    assert_eq!(bytes.len(), 64, "sha256 hex digest has 64 digits");
    let mut digest = [0_u8; 32];
    for (byte, pair) in digest.iter_mut().zip(bytes.chunks_exact(2)) {
        *byte = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    NixSha256Digest::from_bytes(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit {byte:?}"),
    }
}

fn gc_stress_fetch_tarball_expected_store_path(store_dir: &std::path::Path, url: &str) -> Vec<u8> {
    let ir = lower("null");
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(store_dir)).expect("store dir configures");
    let evaluator = TreeWalk::with_options(&ir, options);
    evaluator
        .fetch_tarball_store_path_from_digest(
            IrId::new(0),
            Span::new(0, 0),
            url.as_bytes(),
            "source",
            nix_sha256_digest_from_hex(GC_STRESS_FETCH_TARBALL_DIGEST),
        )
        .expect("fetchTarball expected store path computes")
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetchurl_result_dispatch_permanent_noop_bridge() {
    let (dir, path) = temp_file_with_bytes("gc-stress-fetchurl", b"abc");
    let url = nix_string_literal(&format!("file://{}", path_source(&path)));
    assert_gc_stress_root_string_result_dispatches(
        &format!("builtins.fetchurl {url}"),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt",
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_fetchurl_result_skips_unregistered_outer_locals() {
    let (dir, path) = temp_file_with_bytes("gc-stress-nested-fetchurl", b"abc");
    let url = nix_string_literal(&format!("file://{}", path_source(&path)));
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.fetchurl {url}"#),
        false,
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetch_tarball_string_result_dispatch_permanent_noop_bridge() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-fetch-tarball");
    let store_dir = unique_temp_dir("gc-stress-fetch-tarball-store");
    let url = format!("file://{}", path_source(&archive_path));
    let expected = gc_stress_fetch_tarball_expected_store_path(&store_dir, &url);
    let url = nix_string_literal(&url);
    let source = format!("builtins.fetchTarball {url}");
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_gc_stress_root_string_result_dispatches_with_options(&source, &expected, options);

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetch_tarball_fixed_attrset_results_skip_interned_composite_roots() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-fetch-tarball-fixed");
    let store_dir = unique_temp_dir("gc-stress-fetch-tarball-fixed-store");
    let url = format!("file://{}", path_source(&archive_path));
    let expected = gc_stress_fetch_tarball_expected_store_path(&store_dir, &url);
    let url = nix_string_literal(&url);
    let source = format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{GC_STRESS_FETCH_TARBALL_DIGEST}"; }}"#
    );
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_gc_stress_root_string_result_skips_dispatch_with_options(&source, &expected, options);

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_fetch_tarball_reused_fixed_attrset_result_skips_interned_composite_roots() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-fetch-tarball-reuse");
    let store_dir = unique_temp_dir("gc-stress-fetch-tarball-reuse-store");
    let url = format!("file://{}", path_source(&archive_path));
    let expected = gc_stress_fetch_tarball_expected_store_path(&store_dir, &url);
    let url = nix_string_literal(&url);
    let source = format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{GC_STRESS_FETCH_TARBALL_DIGEST}"; }}"#
    );
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_eq!(
        eval_string_bytes_with_options(&source, options.clone()),
        expected
    );
    fs::remove_dir_all(&archive_dir).expect("archive temp directory removes");

    assert_gc_stress_root_string_result_skips_dispatch_with_options(&source, &expected, options);

    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_fetch_tarball_result_skips_unregistered_outer_locals() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("gc-stress-nested-fetch-tarball");
    let store_dir = unique_temp_dir("gc-stress-nested-fetch-tarball-store");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let source = format!(
        r#""left" == builtins.fetchTarball {{ url = {url}; sha256 = "{GC_STRESS_FETCH_TARBALL_DIGEST}"; }}"#
    );
    let options =
        TreeWalkOptions::with_store_dir(path_bytes(&store_dir)).expect("store dir configures");

    assert_gc_stress_root_bool_result_skips_dispatch_with_options(&source, false, options);

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_file_result_dispatch_permanent_noop_bridge() {
    let (dir, path) = temp_file_with_bytes("gc-stress-read-file", b"abc");
    let path = nix_string_literal(&path_source(&path));
    assert_gc_stress_root_string_result_dispatches(&format!("builtins.readFile {path}"), b"abc");
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_file_type_result_dispatch_permanent_noop_bridge() {
    let (dir, regular) = temp_file_with_bytes("gc-stress-read-file-type", b"abc");
    let nested = dir.join("nested");
    fs::create_dir(&nested).expect("nested directory creates");
    let cases = [
        (
            nix_string_literal(&path_source(&regular)),
            b"regular".as_slice(),
        ),
        (
            nix_string_literal(&path_source(&nested)),
            b"directory".as_slice(),
        ),
    ];

    for (path, expected) in cases {
        assert_gc_stress_root_string_result_dispatches(
            &format!("builtins.readFileType {path}"),
            expected,
        );
    }

    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_file_text_store_result_skips_nested_text_store_setup() {
    assert_gc_stress_root_string_result_skips_dispatch(
        r#"builtins.readFile (builtins.toFile "gc-read" "abc")"#,
        b"abc",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_nested_read_file_result_skips_unregistered_outer_locals() {
    assert_gc_stress_root_bool_result_skips_dispatch(
        r#""left" == builtins.readFile (builtins.toFile "gc-read" "abc")"#,
        false,
    );

    let (dir, path) = temp_file_with_bytes("gc-stress-nested-read-file", b"abc");
    let path = nix_string_literal(&path_source(&path));
    assert_gc_stress_root_bool_result_skips_dispatch(
        &format!(r#""left" == builtins.readFile {path}"#),
        false,
    );
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_read_dir_empty_attrset_result_skips_primop_composite_dispatch() {
    let dir = unique_temp_dir("gc-stress-read-dir-empty");
    let source = format!(
        "builtins.readDir {}",
        nix_string_literal(&path_source(&dir))
    );
    let ir = lower(&source);
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
        .expect("GC-stress readDir evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated readDir attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("readDir result is heap-owned");
    assert_eq!(attrs.len(), 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("readDir result attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_read_dir_entry_type_strings_dispatch_before_attrset_skip() {
    let dir = unique_temp_dir("gc-stress-read-dir-entry-types");
    let regular = dir.join("regular");
    let nested = dir.join("nested");
    fs::write(&regular, b"data").expect("regular file writes");
    fs::create_dir(&nested).expect("nested directory creates");
    let path = path_source(&dir);
    let source = format!("builtins.readDir {}", nix_string_literal(&path));
    let ir = lower(&source);
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
        .expect("readDir argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let argument_value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(path.into_bytes()))
        .expect("argument path string allocates");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
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
            eval.eval_read_dir_primop(ir.root, root.span, argument, argument_span, argument_value)
        })
        .expect("GC-stress non-empty readDir evaluates");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while readDir entry type strings allocated"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let regular_key = evaluator
        .symbols
        .intern(b"regular")
        .expect("regular key interns");
    let nested_key = evaluator
        .symbols
        .intern(b"nested")
        .expect("nested key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("readDir result is heap-owned");
    assert_eq!(
        evaluator
            .heap()
            .get_string(attrs.get(regular_key).expect("regular attr exists"))
            .expect("regular type string is heap-owned")
            .bytes(),
        b"regular"
    );
    assert_eq!(
        evaluator
            .heap()
            .get_string(attrs.get(nested_key).expect("nested attr exists"))
            .expect("nested type string is heap-owned")
            .bytes(),
        b"directory"
    );
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count()
            >= permanent_safepoints_before + 3,
        "two entry type strings and final attrset should allocate under GC stress"
    );
    let final_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("readDir final attrset allocation safepoint records");
    assert_eq!(
        final_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        final_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.thunk_resolve_card_table().is_empty());
    fs::remove_dir_all(dir).expect("temp directory removes");
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_try_eval_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.tryEval 7");
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
        .expect("GC-stress tryEval evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated tryEval attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let success_key = evaluator
        .symbols
        .intern(b"success")
        .expect("success key interns");
    let value_key = evaluator
        .symbols
        .intern(b"value")
        .expect("value key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("tryEval result is heap-owned");
    assert_eq!(
        attrs
            .get(success_key)
            .expect("success attr exists")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        attrs.get(value_key).expect("value attr exists").as_int(),
        Ok(7)
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("tryEval result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_remove_attrs_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.removeAttrs { keep = 7; drop = 1; } [ \"drop\" ]");
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
        .expect("GC-stress removeAttrs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated removeAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let keep_key = evaluator.symbols.intern(b"keep").expect("keep key interns");
    let drop_key = evaluator.symbols.intern(b"drop").expect("drop key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("removeAttrs result is heap-owned");
    assert_eq!(attrs.len(), 1);
    assert_eq!(
        attrs.get(keep_key).expect("keep attr exists").as_int(),
        Ok(7)
    );
    assert!(attrs.get(drop_key).is_none());
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("removeAttrs result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_intersect_attrs_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.intersectAttrs { keep = 0; missing = 0; } { keep = 7; drop = 1; }");
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
        .expect("GC-stress intersectAttrs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated intersectAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let keep_key = evaluator.symbols.intern(b"keep").expect("keep key interns");
    let drop_key = evaluator.symbols.intern(b"drop").expect("drop key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("intersectAttrs result is heap-owned");
    assert_eq!(attrs.len(), 1);
    assert_eq!(
        attrs.get(keep_key).expect("keep attr exists").as_int(),
        Ok(7)
    );
    assert!(attrs.get(drop_key).is_none());
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("intersectAttrs result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_map_attrs_empty_result_allocates_and_skips_primop_composite_dispatch() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let input = evaluator
        .heap
        .alloc_attrs_with_repr_metadata(99, AttrSetReprKind::Flat, FlatAttrs::empty())
        .expect("metadata-distinct empty input attrs allocate");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_map_attrs_primop_value(
                ir.root,
                span,
                EvalPrimOpArg::new(ir.root, span, Value::int(0)),
                EvalPrimOpArg::new(ir.root, span, input),
            )
        })
        .expect("GC-stress mapAttrs result allocates");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated mapAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert!(
        !value.raw_eq(input),
        "empty mapAttrs result reused the input attrset instead of allocating"
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("mapAttrs result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "mapAttrs result should allocate exactly one permanent attrset"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("mapAttrs result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_zip_attrs_with_empty_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.zipAttrsWith (_name: values: values) []");
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
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress zipAttrsWith evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated zipAttrsWith attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("zipAttrsWith result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "zipAttrsWith evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("zipAttrsWith result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_list_to_attrs_empty_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.listToAttrs []");
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
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress listToAttrs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated listToAttrs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("listToAttrs result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "listToAttrs evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("listToAttrs result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_group_by_empty_result_skips_primop_composite_dispatch() {
    let ir = lower(r#"builtins.groupBy (_value: "group") []"#);
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
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress groupBy evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated groupBy attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("groupBy result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "groupBy evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("groupBy result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_function_args_result_skips_primop_composite_dispatch() {
    let ir = lower("builtins.functionArgs ({ a, b ? (1 / 0) }: a)");
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
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress functionArgs evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated functionArgs attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let a_key = evaluator.symbols.intern(b"a").expect("a key interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b key interns");
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("functionArgs result is heap-owned");
    assert_eq!(attrs.len(), 2);
    assert_eq!(
        attrs.get(a_key).expect("a attr exists").as_bool(),
        Ok(false)
    );
    assert_eq!(attrs.get(b_key).expect("b attr exists").as_bool(), Ok(true));
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "functionArgs evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("functionArgs result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_serializer_scalar_results_dispatch_permanent_noop_bridge() {
    assert_gc_stress_root_string_result_dispatches("builtins.toJSON 123", b"123");
    assert_gc_stress_root_string_result_dispatches(
        "builtins.toXML 1",
        b"<?xml version='1.0' encoding='utf-8'?>\n<expr>\n  <int value=\"1\" />\n</expr>\n",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_json_array_result_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
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

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_json(
                ir.root,
                span,
                JsonValue::Array(vec![
                    JsonValue::Number(JsonNumber::from(1)),
                    JsonValue::Bool(true),
                    JsonValue::Null,
                ]),
            )
        })
        .expect("JSON array list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating JSON array list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("JSON array list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("JSON array result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first JSON value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second JSON value exists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        list.get(2).expect("third JSON value exists").as_null(),
        Ok(())
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("JSON array list allocation safepoint records");
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

#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_toml_array_result_dispatches_permanent_noop_bridge() {
    let ir = lower("null");
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

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_toml(
                ir.root,
                span,
                TomlValue::Array(vec![
                    TomlValue::Integer(1),
                    TomlValue::Boolean(true),
                    TomlValue::Float(2.5),
                ]),
            )
        })
        .expect("TOML array list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while allocating TOML array list"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("TOML array list generation is known"),
        HeapGeneration::Permanent
    );
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("TOML array result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first TOML value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second TOML value exists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        list.get(2)
            .expect("third TOML value exists")
            .as_float()
            .map(f64::to_bits),
        Ok(2.5f64.to_bits())
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("TOML array list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_json_empty_object_result_skips_primop_composite_dispatch() {
    let ir = lower("null");
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

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_json(ir.root, span, JsonValue::Object(serde_json::Map::new()))
        })
        .expect("JSON empty object attrset allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated JSON object attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("JSON object attrset generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("JSON object result is heap-owned");
    assert_eq!(attrs.len(), 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("JSON object attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_toml_empty_table_result_skips_primop_composite_dispatch() {
    let ir = lower("null");
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

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.value_from_toml(ir.root, span, TomlValue::Table(Default::default()))
        })
        .expect("TOML empty table attrset allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated TOML table attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(
        evaluator
            .heap()
            .generation(value)
            .expect("TOML table attrset generation is known"),
        HeapGeneration::Permanent
    );
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("TOML table result is heap-owned");
    assert_eq!(attrs.len(), 0);
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("TOML table attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_codec_empty_attrset_results_skip_argument_node_dispatch() {
    for (source, name) in [
        (r#"builtins.fromJSON "{}""#, "fromJSON"),
        (r#"builtins.fromTOML """#, "fromTOML"),
    ] {
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
        let permanent_safepoints_before =
            evaluator.heap().permanent_allocation_safepoints().count();

        let value = evaluator
            .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
            .expect("GC-stress codec primop evaluates");

        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert!(
            roots[0].raw_eq(local_source),
            "registered root relocated while {name} result allocation used a non-root argument id"
        );
        assert_eq!(roots[0].tag(), ValueTag::Thunk);
        assert_eq!(value.tag(), ValueTag::Attrs);
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("codec result is heap-owned");
        assert_eq!(attrs.len(), 0);
        assert!(
            evaluator.heap().permanent_allocation_safepoints().count()
                > permanent_safepoints_before,
            "{name} evaluation should record permanent allocations"
        );
        let permanent_safepoint = evaluator
            .heap()
            .permanent_allocation_safepoints()
            .last()
            .expect("codec result attrset allocation safepoint records");
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
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_formal_set_auto_call_empty_arg_skips_non_attrset_root_dispatch() {
    let ir = lower("{ selected ? 7 }: selected");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let lambda = evaluator.eval_root().expect("formal-set lambda allocates");
    assert_eq!(lambda.tag(), ValueTag::Lambda);
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.auto_call_formal_set_lambda(ir.root, span, lambda)
        })
        .expect("formal-set auto-call evaluates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while auto-call empty attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.as_int(), Ok(7));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "formal-set auto-call should record exactly one permanent attrset safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("formal-set auto-call attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    let stats = evaluator.attr_telemetry.order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_get_context_empty_result_skips_primop_composite_dispatch() {
    let ir = lower(r#"builtins.getContext "x""#);
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
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress getContext evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated getContext attrset dispatch was blocked"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("getContext result is heap-owned");
    assert_eq!(attrs.len(), 0);
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count() > permanent_safepoints_before,
        "getContext evaluation should record permanent allocations"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("getContext result attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_list_string_result_helpers_skip_interned_composite_roots() {
    let cases: &[(&str, &[u8])] = &[
        (r#"builtins.concatStringsSep "," [ "a" "b" ]"#, b"a,b"),
        (r#"builtins.replaceStrings [ "a" ] [ "b" ] "ca""#, b"cb"),
    ];

    for (source, expected) in cases {
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
fn gc_stress_strict_unary_attr_names_list_result_skips_composite_input_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let z = evaluator.symbols.intern(b"z").expect("z interns");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(z, Value::int(2)),
            AttrEntry::new(a, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_strict_unary_primop_value(
                ir.root,
                span,
                StrictUnaryPrimOp::AttrNames,
                ir.root,
                span,
                attrs_value,
            )
        })
        .expect("attrNames helper list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while attrNames input attrset root was live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("attrNames result is heap-owned");
    assert_eq!(list.len(), 2);
    let first = evaluator
        .heap()
        .get_string(list.get(0).expect("first attr name exists"))
        .expect("first attr name is a string");
    let second = evaluator
        .heap()
        .get_string(list.get(1).expect("second attr name exists"))
        .expect("second attr name is a string");
    assert_eq!(first.bytes(), b"a");
    assert_eq!(second.bytes(), b"z");
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "attrNames input attrset root should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("attrNames list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_strict_unary_attr_values_list_result_skips_composite_input_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let a = evaluator.symbols.intern(b"a").expect("a interns");
    let z = evaluator.symbols.intern(b"z").expect("z interns");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(z, Value::int(2)),
            AttrEntry::new(a, Value::int(1)),
        ],
        &evaluator.symbols,
    )
    .expect("attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_strict_unary_primop_value(
                ir.root,
                span,
                StrictUnaryPrimOp::AttrValues,
                ir.root,
                span,
                attrs_value,
            )
        })
        .expect("attrValues helper list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while attrValues input attrset root was live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("attrValues result is heap-owned");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.get(0).expect("first attr value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second attr value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "attrValues input attrset root should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("attrValues list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_strict_unary_tail_list_result_skips_composite_input_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![
            Value::int(0),
            Value::int(1),
            Value::bool(true),
        ]))
        .expect("input list allocates");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_strict_unary_primop_value(
                ir.root,
                span,
                StrictUnaryPrimOp::Tail,
                ir.root,
                span,
                input,
            )
        })
        .expect("tail helper list allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while tail input list root was live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("tail result is heap-owned");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.get(0).expect("first tail value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second tail value exists").as_bool(),
        Ok(true)
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "tail input list root should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("tail list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_alloc_tree_walk_list_skips_active_primop_roots() {
    let ir = lower("null");
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

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[EvalPrimOpArg::new(ir.root, span, Value::int(9))],
        )
        .expect("active primop roots push");
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.alloc_tree_walk_list(ir.root, span, NixList::new(vec![Value::int(1)]))
        })
        .expect("list wrapper allocates with active primop roots");
    evaluator.pop_active_primop_arg_roots();
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated despite active primop roots"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("list wrapper result is heap-owned");
    assert_eq!(list.len(), 1);
    assert_eq!(list.get(0).expect("list value exists").as_int(), Ok(1));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "list wrapper allocation did not record exactly one permanent safepoint"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "active first-class primop argument roots should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_list_concat_result_skips_composite_input_roots() {
    let ir = lower("[ 1 ] ++ [ 2 true ]");
    let node = ir.arena.node(ir.root).expect("root exists");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let left = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("left list allocates");
    let right = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(2), Value::bool(true)]))
        .expect("right list allocates");
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, node.span, &mut roots, |eval| {
            eval.concat_lists(ir.root, node, left, right)
        })
        .expect("list concat result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "list concat result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while list concat input list roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("list concat result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first concat value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second concat value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        list.get(2).expect("third concat value exists").as_bool(),
        Ok(true)
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("list concat allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_concat_lists_primop_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let first = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("first list allocates");
    let second = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(2), Value::bool(true)]))
        .expect("second list allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![first, second]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(ir.root, span, &[EvalPrimOpArg::new(ir.root, span, input)])
        .expect("active concatLists argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_concat_lists_primop(ir.root, span, ir.root, span, input)
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("concatLists result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "concatLists result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active concatLists argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("concatLists result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0)
            .expect("first concatLists value exists")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1)
            .expect("second concatLists value exists")
            .as_int(),
        Ok(2)
    );
    assert_eq!(
        list.get(2)
            .expect("third concatLists value exists")
            .as_bool(),
        Ok(true)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "concatLists result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("concatLists list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_cat_attrs_list_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let key = evaluator.symbols.intern(b"a").expect("a interns");
    let attrs = FlatAttrs::new(vec![AttrEntry::new(key, Value::int(1))], &evaluator.symbols)
        .expect("attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![attrs_value]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(ir.root, span, &[EvalPrimOpArg::new(ir.root, span, input)])
        .expect("active catAttrs argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_cat_attrs_primop_value(
            ir.root,
            span,
            key,
            EvalPrimOpArg::new(ir.root, span, input),
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("catAttrs list result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "catAttrs result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active catAttrs argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("catAttrs result is heap-owned");
    assert_eq!(list.len(), 1);
    assert_eq!(list.get(0).expect("catAttrs value exists").as_int(), Ok(1));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "catAttrs result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("catAttrs list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_cat_attrs_direct_list_result_skips_active_env_roots() {
    let root = IrId::new(0);
    let name_node = IrId::new(1);
    let list_node = IrId::new(2);
    let span = Span::new(0, 0);
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"a").expect("a interns");
    let ir = manual_ir_with_symbols(
        root,
        vec![
            pure_node(IrKind::Null, span, IrData::None),
            pure_node(IrKind::Str, span, IrData::Symbol(key)),
            pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 }),
        ],
        symbols,
    );
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let attrs = FlatAttrs::new(vec![AttrEntry::new(key, Value::int(1))], &evaluator.symbols)
        .expect("attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("attrs allocate");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![attrs_value]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];
    let frame = EvalFrame::new(1).expect("active frame allocates");
    frame.set(0, input).expect("active frame slot sets");

    evaluator.env.push(frame);
    evaluator.active_root_eval_node = Some(root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(root, span, &mut roots, |eval| {
            eval.eval_cat_attrs_primop(root, span, name_node, list_node)
        })
        .expect("direct catAttrs list result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;
    evaluator.env.pop();

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "direct catAttrs result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active catAttrs environment roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("direct catAttrs result is heap-owned");
    assert_eq!(list.len(), 1);
    assert_eq!(list.get(0).expect("catAttrs value exists").as_int(), Ok(1));
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("direct catAttrs list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_partition_list_results_skip_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let right_key = evaluator.symbols.intern(b"right").expect("right interns");
    let wrong_key = evaluator.symbols.intern(b"wrong").expect("wrong interns");
    let skipped = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("skipped string allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1), skipped, Value::int(2)]))
        .expect("input list allocates");
    let predicate_symbol = evaluator.symbols.intern(b"isInt").expect("isInt interns");
    let predicate_builtin = lookup_builtin(b"isInt").expect("isInt builtin exists");
    let predicate = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(predicate_symbol, predicate_builtin))
        .expect("predicate primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, predicate),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active partition argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_partition_elements(
            ir.root,
            span,
            ir.root,
            span,
            predicate,
            ir.root,
            span,
            vec![Value::int(1), skipped, Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("partition result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 2,
        "partition right/wrong lists did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active partition argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("partition result is heap-owned");
    let right = attrs.get(right_key).expect("right partition exists");
    let wrong = attrs.get(wrong_key).expect("wrong partition exists");
    let right = evaluator
        .heap()
        .get_list(right)
        .expect("right partition is heap-owned");
    assert_eq!(right.len(), 2);
    assert_eq!(
        right.get(0).expect("first right value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        right.get(1).expect("second right value exists").as_int(),
        Ok(2)
    );
    let wrong = evaluator
        .heap()
        .get_list(wrong)
        .expect("wrong partition is heap-owned");
    assert_eq!(wrong.len(), 1);
    assert!(wrong.get(0).expect("wrong value exists").raw_eq(skipped));
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert_eq!(
        permanent_safepoints.count(),
        permanent_safepoints_before + 3,
        "partition result did not record the two list safepoints plus attrs safepoint"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("partition attrs allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_concat_map_result_skips_active_argument_roots() {
    let ir = lower("x: x");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("identity function allocates");
    assert_eq!(function.tag(), ValueTag::Lambda);
    let skipped = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("skipped string allocates");
    let first = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("first input list allocates");
    let second = evaluator
        .heap
        .alloc_list(NixList::new(vec![skipped, Value::int(2)]))
        .expect("second input list allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![first, second]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active concatMap argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_concat_map_elements(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![first, second],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("concatMap result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "concatMap result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active concatMap argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("concatMap result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first concatMap value exists").as_int(),
        Ok(1)
    );
    assert!(
        list.get(1)
            .expect("second concatMap value exists")
            .raw_eq(skipped)
    );
    assert_eq!(
        list.get(2).expect("third concatMap value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "concatMap result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("concatMap list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_group_by_bucket_lists_skip_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let int_key = evaluator.symbols.intern(b"int").expect("int interns");
    let string_key = evaluator.symbols.intern(b"string").expect("string interns");
    let string_value = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("string input allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![
            Value::int(1),
            string_value,
            Value::int(2),
        ]))
        .expect("input list allocates");
    let function_symbol = evaluator.symbols.intern(b"typeOf").expect("typeOf interns");
    let function_builtin = lookup_builtin(b"typeOf").expect("typeOf builtin exists");
    let function = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(function_symbol, function_builtin))
        .expect("function primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active groupBy argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_group_by_elements(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![Value::int(1), string_value, Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("groupBy result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 2,
        "groupBy bucket lists did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active groupBy argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("groupBy result is heap-owned");
    let int_group = attrs.get(int_key).expect("int group exists");
    let string_group = attrs.get(string_key).expect("string group exists");
    let int_group = evaluator
        .heap()
        .get_list(int_group)
        .expect("int group is heap-owned");
    assert_eq!(int_group.len(), 2);
    assert_eq!(
        int_group
            .get(0)
            .expect("first int group value exists")
            .as_int(),
        Ok(1)
    );
    assert_eq!(
        int_group
            .get(1)
            .expect("second int group value exists")
            .as_int(),
        Ok(2)
    );
    let string_group = evaluator
        .heap()
        .get_list(string_group)
        .expect("string group is heap-owned");
    assert_eq!(string_group.len(), 1);
    assert!(
        string_group
            .get(0)
            .expect("string group value exists")
            .raw_eq(string_value)
    );
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert!(
        permanent_safepoints.count() >= permanent_safepoints_before + 3,
        "groupBy result did not record at least the two bucket-list safepoints plus attrs safepoint"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("groupBy attrs allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_sort_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let comparator_symbol = evaluator
        .symbols
        .intern(b"lessThan")
        .expect("lessThan interns");
    let comparator_builtin = lookup_builtin(b"lessThan").expect("lessThan builtin exists");
    let comparator = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(
            comparator_symbol,
            comparator_builtin,
        ))
        .expect("comparator primop allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![
            Value::int(3),
            Value::int(1),
            Value::int(2),
        ]))
        .expect("input list allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, comparator),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active sort argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_sort_elements(
            ir.root,
            span,
            ir.root,
            span,
            comparator,
            ir.root,
            span,
            vec![Value::int(3), Value::int(1), Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("sort result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "sort result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active sort argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("sort result is heap-owned");
    assert_eq!(list.len(), 3);
    assert_eq!(
        list.get(0).expect("first sorted value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second sorted value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        list.get(2).expect("third sorted value exists").as_int(),
        Ok(3)
    );
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert!(
        permanent_safepoints.count() >= permanent_safepoints_before + 1,
        "sort result allocation did not record a permanent safepoint"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("sort list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_generic_closure_empty_result_routes_through_list_wrapper() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let start_set = evaluator
        .heap
        .alloc_list(NixList::new(Vec::new()))
        .expect("startSet list allocates");
    let start_set_symbol = evaluator
        .symbols
        .intern(START_SET_ATTR)
        .expect("startSet interns");
    let argument_attrs = FlatAttrs::new(
        vec![AttrEntry::new(start_set_symbol, start_set)],
        &evaluator.symbols,
    )
    .expect("genericClosure argument attrs build");
    let argument = evaluator
        .heap
        .alloc_attrs(0, argument_attrs)
        .expect("genericClosure argument attrs allocate");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_generic_closure_primop(ir.root, span, ir.root, span, argument)
        })
        .expect("genericClosure empty result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "genericClosure empty result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root changed while routing genericClosure empty result"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("genericClosure empty result is heap-owned");
    assert!(list.is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_generic_closure_result_routes_through_list_wrapper() {
    let ir = lower("item: if item.key == 1 then [ { key = 2; } ] else []");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let operator = evaluator
        .eval_node(ir.root)
        .expect("genericClosure operator allocates");
    assert_eq!(operator.tag(), ValueTag::Lambda);
    let key_symbol = evaluator.symbols.intern(b"key").expect("key interns");
    let item_attrs = FlatAttrs::new(
        vec![AttrEntry::new(key_symbol, Value::int(1))],
        &evaluator.symbols,
    )
    .expect("item attrs build");
    let item = evaluator
        .heap
        .alloc_attrs(0, item_attrs)
        .expect("item attrs allocate");
    let start_set = evaluator
        .heap
        .alloc_list(NixList::new(vec![item]))
        .expect("startSet list allocates");
    let start_set_symbol = evaluator
        .symbols
        .intern(START_SET_ATTR)
        .expect("startSet interns");
    let operator_symbol = evaluator
        .symbols
        .intern(OPERATOR_ATTR)
        .expect("operator interns");
    let argument_attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(start_set_symbol, start_set),
            AttrEntry::new(operator_symbol, operator),
        ],
        &evaluator.symbols,
    )
    .expect("genericClosure argument attrs build");
    let argument = evaluator
        .heap
        .alloc_attrs(0, argument_attrs)
        .expect("genericClosure argument attrs allocate");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
            eval.eval_generic_closure_primop(ir.root, span, ir.root, span, argument)
        })
        .expect("genericClosure result allocates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 3,
        "genericClosure generated lists and final result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root changed while routing genericClosure result"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let result_items = {
        let result = evaluator
            .heap()
            .get_list(value)
            .expect("genericClosure result is heap-owned");
        assert_eq!(result.len(), 2);
        [
            result.get(0).expect("first result item exists"),
            result.get(1).expect("second result item exists"),
        ]
    };
    assert!(result_items[0].raw_eq(item));
    let generated = evaluator
        .heap()
        .get_attrs(result_items[1])
        .expect("generated item is heap-owned");
    let generated_key = generated.get(key_symbol).expect("generated key exists");
    assert_eq!(
        evaluator
            .force_value(ir.root, span, generated_key)
            .expect("generated key forces")
            .as_int(),
        Ok(2)
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("genericClosure result safepoint records");
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

fn apply2_thunk_values(evaluator: &TreeWalk, value: Value) -> (Value, Value, Value) {
    let thunk = evaluator
        .heap()
        .get_thunk(value)
        .expect("apply2 result is a thunk");
    let EvalThunkKind::Apply2 {
        function_value,
        first_argument_value,
        second_argument_value,
        ..
    } = thunk.kind()
    else {
        panic!("result is an apply2 thunk");
    };
    (
        *function_value,
        *first_argument_value,
        *second_argument_value,
    )
}

fn zipped_apply2_second_argument(evaluator: &TreeWalk, value: Value) -> Value {
    apply2_thunk_values(evaluator, value).2
}

fn assert_heap_string_bytes(evaluator: &TreeWalk, value: Value, expected: &[u8]) {
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("value is a heap-owned string");
    assert_eq!(string.bytes(), expected);
}

fn assert_nix_path_entry(
    evaluator: &mut TreeWalk,
    value: Value,
    expected_prefix: &[u8],
    expected_path: &[u8],
) {
    let path_key = evaluator.symbols.intern(b"path").expect("path key interns");
    let prefix_key = evaluator
        .symbols
        .intern(b"prefix")
        .expect("prefix key interns");
    let (path, prefix) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("nixPath entry is a heap-owned attrset");
        assert_eq!(attrs.len(), 2);
        (
            attrs.get(path_key).expect("path attr exists"),
            attrs.get(prefix_key).expect("prefix attr exists"),
        )
    };
    assert_heap_string_bytes(evaluator, prefix, expected_prefix);
    assert_heap_string_bytes(evaluator, path, expected_path);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_map_attrs_symbol_names_preserve_live_locals() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    // FV-3: the GC-stress scan machinery operates on record-table worker
    // objects; select the scaffolding placement before any allocation so
    // the late stress-policy install below sees a record population.
    evaluator
        .heap
        .use_record_worker_closures_for_gc_scaffolding();
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(31)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(37)))
        .expect("right value thunk allocates");

    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
        .expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(
        !a_function.raw_eq(function),
        "first mapAttrs function handle was not relocated before thunk capture"
    );
    assert!(
        !b_function.raw_eq(function),
        "second mapAttrs function handle was not written back after relocation"
    );
    evaluator
        .heap()
        .get_lambda(a_function)
        .expect("first mapAttrs function remains heap-owned");
    evaluator
        .heap()
        .get_lambda(b_function)
        .expect("second mapAttrs function remains heap-owned");
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(
        !a_value.raw_eq(left),
        "current mapAttrs value was not relocated before thunk capture"
    );
    assert!(
        !b_value.raw_eq(right),
        "unprocessed mapAttrs entry tail was not written back after relocation"
    );
    assert_eq!(a_value.tag(), ValueTag::Thunk);
    assert_eq!(b_value.tag(), ValueTag::Thunk);
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "mapAttrs should dispatch the two symbol-name string allocations"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_map_attrs_symbol_names_dispatch_with_active_function_argument_root() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    // FV-3: the GC-stress scan machinery operates on record-table worker
    // objects; select the scaffolding placement before any allocation so
    // the late stress-policy install below sees a record population.
    evaluator
        .heap
        .use_record_worker_closures_for_gc_scaffolding();
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(41)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(43)))
        .expect("right value thunk allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(47)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, Value::int(2)),
            ],
        )
        .expect("active mapAttrs argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
    });
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        !roots[0].raw_eq(local_source),
        "registered root was not relocated while active function argument root was admitted"
    );
    assert_eq!(roots[0].tag(), ValueTag::Thunk);
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(
        !a_function.raw_eq(function),
        "first mapAttrs function argument was not relocated before thunk capture"
    );
    assert!(
        !b_function.raw_eq(function),
        "second mapAttrs function argument was not written back after relocation"
    );
    evaluator
        .heap()
        .get_lambda(a_function)
        .expect("first mapAttrs function remains heap-owned");
    evaluator
        .heap()
        .get_lambda(b_function)
        .expect("second mapAttrs function remains heap-owned");
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(
        !a_value.raw_eq(left),
        "current mapAttrs value was not relocated before thunk capture"
    );
    assert!(
        !b_value.raw_eq(right),
        "unprocessed mapAttrs entry tail was not written back after relocation"
    );
    assert!(
        evaluator.heap().permanent_allocation_safepoints().count()
            >= permanent_safepoints_before + 3,
        "mapAttrs result did not record expected permanent allocations"
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        &[
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocString,
        ],
        "admitted mapAttrs function argument should allow the two symbol-name string dispatches"
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
fn gc_stress_map_attrs_symbol_names_skip_unregistered_active_argument_root() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(61)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(67)))
        .expect("right value thunk allocates");
    let attrs = FlatAttrs::new(
        vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        &evaluator.symbols,
    )
    .expect("input attrs build");
    let attrs_value = evaluator
        .heap
        .alloc_attrs(0, attrs)
        .expect("input attrs allocate");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(71)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, attrs_value),
            ],
        )
        .expect("active mapAttrs argument roots push");
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
    });
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while unregistered active mapAttrs argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(a_function.raw_eq(function));
    assert!(b_function.raw_eq(function));
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(a_value.raw_eq(left));
    assert!(b_value.raw_eq(right));
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "unregistered active mapAttrs argument root should block symbol-name dispatch"
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
fn gc_stress_map_attrs_symbol_names_skip_nested_active_argument_frames() {
    let ir = lower("name: value: value");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("mapAttrs function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(51)))
        .expect("left value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(53)))
        .expect("right value thunk allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(57)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[EvalPrimOpArg::new(ir.root, span, Value::int(1))],
        )
        .expect("outer active argument roots push");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, Value::int(2)),
            ],
        )
        .expect("inner active mapAttrs argument roots push");
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_attrs(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, right)],
        )
    });
    evaluator.pop_active_primop_arg_roots();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("mapAttrs result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while nested active primop argument frames were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("mapAttrs result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_value) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_value) = apply2_thunk_values(&evaluator, b_thunk);

    assert!(a_function.raw_eq(function));
    assert!(b_function.raw_eq(function));
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    assert!(a_value.raw_eq(left));
    assert!(b_value.raw_eq(right));
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "nested active primop argument frames should block mapAttrs symbol-name dispatch"
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
fn gc_stress_zip_attrs_with_symbol_names_preserve_values_lists() {
    let ir = lower("name: values: values");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("zipAttrsWith function allocates");
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let left = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(41)))
        .expect("left value thunk allocates");
    let middle = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(43)))
        .expect("middle value thunk allocates");
    let right = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(47)))
        .expect("right value thunk allocates");
    let first_attrs = FlatAttrs::new(
        vec![AttrEntry::new(a_key, left), AttrEntry::new(b_key, middle)],
        &evaluator.symbols,
    )
    .expect("first attrs build");
    let first = evaluator
        .heap
        .alloc_attrs(0, first_attrs)
        .expect("first attrs allocate");
    let second_attrs = FlatAttrs::new(vec![AttrEntry::new(a_key, right)], &evaluator.symbols)
        .expect("second attrs build");
    let second = evaluator
        .heap
        .alloc_attrs(0, second_attrs)
        .expect("second attrs allocate");

    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    evaluator.active_root_eval_node = Some(ir.root);
    let value = evaluator
        .alloc_zipped_attrs_with(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            span,
            vec![first, second],
        )
        .expect("zipAttrsWith result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("zipAttrsWith result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let (a_function, a_name, a_values) = apply2_thunk_values(&evaluator, a_thunk);
    let (b_function, b_name, b_values) = apply2_thunk_values(&evaluator, b_thunk);

    evaluator
        .heap()
        .get_lambda(a_function)
        .expect("first zipAttrsWith function remains heap-owned");
    evaluator
        .heap()
        .get_lambda(b_function)
        .expect("second zipAttrsWith function remains heap-owned");
    assert_heap_string_bytes(&evaluator, a_name, b"a");
    assert_heap_string_bytes(&evaluator, b_name, b"b");
    let a_items = {
        let list = evaluator
            .heap()
            .get_list(a_values)
            .expect("a grouped values are heap-owned");
        assert_eq!(list.len(), 2);
        [
            list.get(0).expect("first a value exists"),
            list.get(1).expect("second a value exists"),
        ]
    };
    let b_item = {
        let list = evaluator
            .heap()
            .get_list(b_values)
            .expect("b grouped values are heap-owned");
        assert_eq!(list.len(), 1);
        list.get(0).expect("b value exists")
    };
    assert_eq!(a_items[0].tag(), ValueTag::Thunk);
    assert_eq!(a_items[1].tag(), ValueTag::Thunk);
    assert_eq!(b_item.tag(), ValueTag::Thunk);
    evaluator
        .heap()
        .get_thunk(a_items[0])
        .expect("first zipAttrsWith grouped value remains heap-owned");
    evaluator
        .heap()
        .get_thunk(a_items[1])
        .expect("second zipAttrsWith grouped value remains heap-owned");
    evaluator
        .heap()
        .get_thunk(b_item)
        .expect("remaining zipAttrsWith group tail remains heap-owned");
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 5,
        "zipAttrsWith should allocate two grouped value lists, two symbol-name strings, and the final attrset"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "zipAttrsWith symbol-name safepoints should remain blocked by live composite input roots"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("zipAttrsWith final attrset allocation safepoint records");
    assert_eq!(
        permanent_safepoint.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocAttrs
    );
    assert_eq!(
        permanent_safepoint.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_zip_attrs_with_direct_root_value_lists_preserve_live_locals() {
    let ir = lower(
        r#"
builtins.zipAttrsWith (name: values: values) [
  { a = "left"; b = "middle"; }
  { a = "right"; }
]
"#,
    );
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let value = evaluator
        .eval_root()
        .expect("root zipAttrsWith evaluates under GC stress");
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();

    assert!(
        wrapper_calls_after >= wrapper_calls_before + 2,
        "root zipAttrsWith grouped value lists did not route through the tree-walk list wrapper"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let (a_thunk, b_thunk) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("zipAttrsWith result is heap-owned");
        (
            attrs.get(a_key).expect("a result exists"),
            attrs.get(b_key).expect("b result exists"),
        )
    };
    let a_values = evaluator
        .force_value(ir.root, span, a_thunk)
        .expect("a grouped values thunk forces");
    let b_values = evaluator
        .force_value(ir.root, span, b_thunk)
        .expect("b grouped values thunk forces");
    let a_items = {
        let list = evaluator
            .heap()
            .get_list(a_values)
            .expect("a grouped values are heap-owned");
        assert_eq!(list.len(), 2);
        [
            list.get(0).expect("first a value exists"),
            list.get(1).expect("second a value exists"),
        ]
    };
    let b_item = {
        let list = evaluator
            .heap()
            .get_list(b_values)
            .expect("b grouped values are heap-owned");
        assert_eq!(list.len(), 1);
        list.get(0).expect("b value exists")
    };
    let first_a = evaluator
        .force_value(ir.root, span, a_items[0])
        .expect("first a grouped value forces");
    let second_a = evaluator
        .force_value(ir.root, span, a_items[1])
        .expect("second a grouped value forces");
    let b = evaluator
        .force_value(ir.root, span, b_item)
        .expect("b grouped value forces");

    assert_heap_string_bytes(&evaluator, first_a, b"left");
    assert_heap_string_bytes(&evaluator, second_a, b"right");
    assert_heap_string_bytes(&evaluator, b, b"middle");
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_zip_attrs_with_value_lists_skip_active_argument_roots() {
    let ir = lower("name: values: values");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function = evaluator
        .eval_node(ir.root)
        .expect("zipAttrsWith function allocates");
    assert_eq!(function.tag(), ValueTag::Lambda);
    let a_key = evaluator.symbols.intern(b"a").expect("a interns");
    let b_key = evaluator.symbols.intern(b"b").expect("b interns");
    let first_attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(a_key, Value::int(1)),
            AttrEntry::new(b_key, Value::int(2)),
        ],
        &evaluator.symbols,
    )
    .expect("first attrs build");
    let first = evaluator
        .heap
        .alloc_attrs(0, first_attrs)
        .expect("first attrs allocate");
    let second_attrs = FlatAttrs::new(
        vec![AttrEntry::new(a_key, Value::int(3))],
        &evaluator.symbols,
    )
    .expect("second attrs build");
    let second = evaluator
        .heap
        .alloc_attrs(0, second_attrs)
        .expect("second attrs allocate");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, function),
                EvalPrimOpArg::new(ir.root, span, Value::int(2)),
            ],
        )
        .expect("active zipAttrsWith argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_zipped_attrs_with(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            span,
            vec![first, second],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("zipAttrsWith result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 2,
        "zipAttrsWith grouped value lists did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active zipAttrsWith argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let attrs = evaluator
        .heap()
        .get_attrs(value)
        .expect("zipAttrsWith result is heap-owned");
    let a_value = attrs.get(a_key).expect("a result exists");
    let b_value = attrs.get(b_key).expect("b result exists");
    let a_values = zipped_apply2_second_argument(&evaluator, a_value);
    let b_values = zipped_apply2_second_argument(&evaluator, b_value);
    let a_values = evaluator
        .heap()
        .get_list(a_values)
        .expect("a grouped values list is heap-owned");
    assert_eq!(a_values.len(), 2);
    assert_eq!(
        a_values.get(0).expect("first a value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        a_values.get(1).expect("second a value exists").as_int(),
        Ok(3)
    );
    let b_values = evaluator
        .heap()
        .get_list(b_values)
        .expect("b grouped values list is heap-owned");
    assert_eq!(b_values.len(), 1);
    assert_eq!(b_values.get(0).expect("b value exists").as_int(), Ok(2));
    let permanent_safepoints = evaluator.heap().permanent_allocation_safepoints();
    assert!(
        permanent_safepoints.count() >= permanent_safepoints_before + 3,
        "zipAttrsWith result did not record expected permanent allocations after grouped value-list wrapper calls"
    );
    let permanent_safepoint = permanent_safepoints
        .last()
        .expect("zipAttrsWith attrs allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_filter_result_skips_active_argument_roots() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let skipped = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"x".to_vec()))
        .expect("skipped string allocates");
    let input = evaluator
        .heap
        .alloc_list(NixList::new(vec![Value::int(1), skipped, Value::int(2)]))
        .expect("input list allocates");
    let predicate_symbol = evaluator.symbols.intern(b"isInt").expect("isInt interns");
    let predicate_builtin = lookup_builtin(b"isInt").expect("isInt builtin exists");
    let predicate = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(predicate_symbol, predicate_builtin))
        .expect("predicate primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            span,
            &[
                EvalPrimOpArg::new(ir.root, span, predicate),
                EvalPrimOpArg::new(ir.root, span, input),
            ],
        )
        .expect("active filter argument roots push");
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.eval_filter_elements(
            ir.root,
            span,
            ir.root,
            span,
            predicate,
            ir.root,
            vec![Value::int(1), skipped, Value::int(2)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    evaluator.pop_active_primop_arg_roots();
    let value = result.expect("filter result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "filter result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while active filter argument roots were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("filter result is heap-owned");
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.get(0).expect("first filter value exists").as_int(),
        Ok(1)
    );
    assert_eq!(
        list.get(1).expect("second filter value exists").as_int(),
        Ok(2)
    );
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "filter result allocation did not record exactly one permanent safepoint"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("filter list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_filter_map_empty_direct_results_route_through_list_wrapper() {
    for (label, eval_empty_result) in [
        (
            "filter",
            TreeWalk::eval_filter_primop
                as fn(&mut TreeWalk, IrId, Span, IrId, IrId) -> Result<Value, TreeWalkError>,
        ),
        (
            "map",
            TreeWalk::eval_map_primop
                as fn(&mut TreeWalk, IrId, Span, IrId, IrId) -> Result<Value, TreeWalkError>,
        ),
    ] {
        let ir = lower("[]");
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

        evaluator.active_root_eval_node = Some(ir.root);
        let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
        let value = evaluator
            .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
                eval_empty_result(eval, ir.root, span, ir.root, ir.root)
            })
            .expect("empty direct list builtin result evaluates under GC stress");
        let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
        evaluator.active_root_eval_node = None;

        assert_eq!(
            wrapper_calls_after,
            wrapper_calls_before + 2,
            "{label} input literal and empty result did not route through the tree-walk list wrapper"
        );
        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert_eq!(roots[0].tag(), ValueTag::Thunk);
        assert_eq!(value.tag(), ValueTag::List);
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("empty direct result is heap-owned");
        assert!(list.is_empty());
        assert!(evaluator.thunk_resolve_card_table().is_empty());
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_filter_map_empty_primop_value_results_route_through_list_wrapper() {
    for (label, eval_empty_result) in [
        (
            "filter",
            TreeWalk::eval_filter_primop_value
                as fn(
                    &mut TreeWalk,
                    IrId,
                    Span,
                    EvalPrimOpArg,
                    EvalPrimOpArg,
                ) -> Result<Value, TreeWalkError>,
        ),
        (
            "map",
            TreeWalk::eval_map_primop_value
                as fn(
                    &mut TreeWalk,
                    IrId,
                    Span,
                    EvalPrimOpArg,
                    EvalPrimOpArg,
                ) -> Result<Value, TreeWalkError>,
        ),
    ] {
        let ir = lower("null");
        let span = ir.arena.node(ir.root).expect("root exists").span;
        let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
        let input = evaluator
            .heap
            .alloc_list(NixList::new(Vec::new()))
            .expect("empty input list allocates");
        evaluator
            .heap
            .set_gc_stress_policy(GcStressPolicy::every_safepoint());
        let local_source = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(7)))
            .expect("registered local thunk allocates");
        let mut roots = [local_source];

        evaluator.active_root_eval_node = Some(ir.root);
        let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
        let value = evaluator
            .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
                eval_empty_result(
                    eval,
                    ir.root,
                    span,
                    EvalPrimOpArg::new(ir.root, span, Value::int(1)),
                    EvalPrimOpArg::new(ir.root, span, input),
                )
            })
            .expect("empty primop-value list builtin result evaluates under GC stress");
        let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
        evaluator.active_root_eval_node = None;

        assert_eq!(
            wrapper_calls_after,
            wrapper_calls_before + 1,
            "{label} empty primop-value result did not route through the tree-walk list wrapper"
        );
        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert!(
            roots[0].raw_eq(local_source),
            "registered root changed while routing empty {label} primop-value result"
        );
        assert_eq!(value.tag(), ValueTag::List);
        let list = evaluator
            .heap()
            .get_list(value)
            .expect("empty primop-value result is heap-owned");
        assert!(list.is_empty());
        assert!(evaluator.thunk_resolve_card_table().is_empty());
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_mapped_list_result_skips_apply_thunk_fields() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let function_symbol = evaluator.symbols.intern(b"isInt").expect("isInt interns");
    let function_builtin = lookup_builtin(b"isInt").expect("isInt builtin exists");
    let function = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(function_symbol, function_builtin))
        .expect("function primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_mapped_list(
            ir.root,
            span,
            ir.root,
            span,
            function,
            ir.root,
            vec![Value::int(1), Value::bool(true)],
        )
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    let value = result.expect("mapped list result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "mapped list result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while mapped apply-thunk fields were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("mapped list result is heap-owned");
    assert_eq!(list.len(), 2);
    for index in 0..2 {
        assert_eq!(
            list.get(index).expect("mapped element exists").tag(),
            ValueTag::Thunk
        );
    }
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "mapped list allocation did not record exactly one permanent safepoint"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "mapped apply-thunk fields should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("mapped list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_generated_list_result_skips_apply_thunk_fields() {
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let mut evaluator = TreeWalk::with_options(&ir, TreeWalkOptions::new());
    let generator_symbol = evaluator.symbols.intern(b"isInt").expect("isInt interns");
    let generator_builtin = lookup_builtin(b"isInt").expect("isInt builtin exists");
    let generator = evaluator
        .heap
        .alloc_primop(EvalPrimOp::registered(generator_symbol, generator_builtin))
        .expect("generator primop allocates");
    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    evaluator.active_root_eval_node = Some(ir.root);
    let permanent_safepoints_before = evaluator.heap().permanent_allocation_safepoints().count();
    let permanent_dispatches_before = evaluator
        .gc_stress_permanent_root_allocation_dispatches()
        .len();
    let wrapper_calls_before = evaluator.tree_walk_list_wrapper_calls();
    let result = evaluator.with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| {
        eval.alloc_generated_list(ir.root, span, ir.root, span, generator, ir.root, 2)
    });
    let wrapper_calls_after = evaluator.tree_walk_list_wrapper_calls();
    let value = result.expect("generated list result allocates under GC stress");
    evaluator.active_root_eval_node = None;

    assert_eq!(
        wrapper_calls_after,
        wrapper_calls_before + 1,
        "generated list result did not route through the tree-walk list wrapper"
    );
    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while generated apply-thunk fields were live"
    );
    assert_eq!(value.tag(), ValueTag::List);
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("generated list result is heap-owned");
    assert_eq!(list.len(), 2);
    for index in 0..2 {
        assert_eq!(
            list.get(index).expect("generated element exists").tag(),
            ValueTag::Thunk
        );
    }
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + 1,
        "generated list allocation did not record exactly one permanent safepoint"
    );
    assert_eq!(
        evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len(),
        permanent_dispatches_before,
        "generated apply-thunk fields should block permanent-root list dispatch"
    );
    let permanent_safepoint = evaluator
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("generated list allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_eval_root_reflected_context_result_helpers_skip_interned_composite_roots() {
    assert_gc_stress_root_string_result_skips_dispatch(
        r#"builtins.appendContext "x" { "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; }; }"#,
        b"x",
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

        let permanent_safepoints_before =
            evaluator.heap().permanent_allocation_safepoints().count();
        let permanent_dispatches_before = evaluator
            .gc_stress_permanent_root_allocation_dispatches()
            .len();
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
        assert_eq!(
            evaluator.heap().permanent_allocation_safepoints().count(),
            permanent_safepoints_before + 1,
            "{source} should allocate exactly one context result string"
        );
        assert_eq!(
            &evaluator.gc_stress_permanent_root_allocation_dispatches()
                [permanent_dispatches_before..],
            &[RuntimeAllocationEntryPoint::AosAllocString],
            "{source} should dispatch exactly one permanent context result string allocation"
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

fn heap_record_forwarding_slot_count(heap: &EvalHeap, values: &[Value]) -> usize {
    values
        .iter()
        .filter(|value| {
            heap.minor_gc_forwarding_value_at(gc_address(**value))
                .expect("forwarding slot lookup succeeds")
                .is_some()
        })
        .count()
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_list_accumulator_thunk_allocations_publish_accumulated_roots() {
    let ir = lower("[ (x: x) (y: y) ]");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress multi-element list evaluates with local accumulator writebacks");

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
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) > elements.len());
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_list_accumulator_allocation_node_clears_after_child_error() {
    let span = Span::new(0, 1);
    let body = IrId::new(0);
    let first_child = IrId::new(1);
    let error_child = IrId::new(2);
    let root = IrId::new(3);
    let ir = empty_ir(
        root,
        IrArena::from_raw_parts(
            vec![
                pure_node(IrKind::Int, span, IrData::Int(7)),
                pure_node(IrKind::ThunkAlloc, span, IrData::Node(body)),
                pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 }),
                pure_node(
                    IrKind::List,
                    span,
                    IrData::Children(IrChildSlice::new(0, 2)),
                ),
            ],
            vec![first_child, error_child],
        ),
    );
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let error = evaluator
        .eval_root()
        .expect_err("invalid list child reports evaluation error");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingEnvironment { id: error_child }
    );
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert!(heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values) >= 1);
    assert_eq!(evaluator.active_root_eval_node, None);
    assert_eq!(evaluator.active_gc_stress_accumulator_allocation_node, None);
    assert!(evaluator.transient_value_stack_roots().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) >= 1);

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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_attrs_accumulator_thunk_allocations_publish_accumulated_roots() {
    let ir = lower("{ a = x: x; b = y: y; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress multi-attr attrset evaluates with local accumulator writebacks");

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
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) > values.len());
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_dynamic_attrs_accumulator_thunk_allocations_publish_accumulated_roots() {
    let ir = lower(r#"{ a = x: x; ${"b"} = y: y; }"#);
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress dynamic-key attrset evaluates with local accumulator writebacks");

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
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) > values.len());
    let permanent_safepoint = outcome
        .heap()
        .permanent_allocation_safepoints()
        .last()
        .expect("root dynamic-key attrset allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_mixed_inherited_attrs_accumulator_thunk_allocations_publish_select_roots() {
    let ir = lower("{ inherit ({ a = 1; }) a; b = x: x; }");
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let default_outcome = eval_whnf_owned(&ir).expect("default mixed inherited attrset evaluates");

    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("GC-stress mixed inherited attrset evaluates with local accumulator writebacks");

    assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    let (selected, ordinary) = {
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("inherited attr exists"),
            attrs.get(b).expect("ordinary attr exists"),
        )
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
    assert_eq!(ordinary.tag(), ValueTag::Thunk);
    assert_eq!(
        outcome
            .heap()
            .generation(ordinary)
            .expect("ordinary attr value generation is known"),
        HeapGeneration::Young
    );

    let thunk_values = heap_record_values_with_tag(outcome.heap(), ValueTag::Thunk);
    assert!(thunk_values.iter().any(|value| value.raw_eq(selected)));
    assert!(thunk_values.iter().any(|value| value.raw_eq(ordinary)));
    assert!(heap_record_forwarding_slot_count(outcome.heap(), &thunk_values) >= 1);
    assert!(
        outcome.heap().allocation_safepoints().count()
            > default_outcome.heap().allocation_safepoints().count()
    );
    let final_worker_safepoint = outcome
        .heap()
        .allocation_safepoints()
        .last()
        .expect("ordinary attr thunk allocation safepoint records");
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_dynamic_attr_key_expression_preserves_registered_roots() {
    let ir = lower(r#"{ inherit ({ a = 1; }) a; ${"b"} = 2; }"#);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let default_outcome =
        eval_whnf_owned(&ir).expect("default dynamic inherited attrset evaluates");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(97)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress dynamic inherited attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while dynamic attr key expression was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (selected, dynamic_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("inherited attr exists"),
            attrs.get(b).expect("dynamic attr exists"),
        )
    };
    assert_eq!(selected.tag(), ValueTag::Thunk);
    let selected_thunk = evaluator
        .heap()
        .get_thunk(selected)
        .expect("inherited select is a heap-owned thunk");
    assert!(matches!(
        selected_thunk.kind(),
        EvalThunkKind::Select { .. }
    ));
    assert_eq!(dynamic_value.as_int(), Ok(2));
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        default_outcome
            .heap()
            .permanent_allocation_safepoints()
            .count(),
        "dynamic-key expression should not add an extra permanent allocation safepoint"
    );
    let permanent_safepoint = evaluator
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
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_recursive_override_binding_assembly_preserves_registered_roots() {
    let ir = lower(r#"rec { a = x: x; __overrides = { b = y: y; }; ${"c"} = z: z; }"#);
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let c = symbol_for(&ir, b"c");
    let overrides = symbol_for(&ir, b"__overrides");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(98)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress recursive override attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while recursive override binding assembly was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_value, b_value, c_value, overrides_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("override b exists"),
            attrs.get(c).expect("dynamic c exists"),
            attrs.get(overrides).expect("__overrides exists"),
        )
    };
    assert_eq!(overrides_value.tag(), ValueTag::Thunk);
    for value in [a_value, b_value, c_value] {
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap()
            .get_thunk(value)
            .expect("binding value is a heap-owned thunk");
        assert!(thunk.env().is_some_and(|env| !env.frames().is_empty()));
    }
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(
        heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values),
        0
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
fn gc_stress_let_binding_assembly_preserves_registered_roots() {
    let ir = lower("let a = x: x; b = y: y; in { inherit a b; }");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(99)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress let binding attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while let binding assembly was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_value, b_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    for value in [a_value, b_value] {
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap()
            .get_thunk(value)
            .expect("binding value is a heap-owned thunk");
        assert!(thunk.env().is_some_and(|env| !env.frames().is_empty()));
    }
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(
        heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values),
        0
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
fn gc_stress_lambda_default_binding_assembly_preserves_registered_roots() {
    let ir = lower("let captured = x: x; in ({ a ? captured, b ? (y: y) }: { inherit a b; }) { }");
    let span = ir.arena.node(ir.root).expect("root exists").span;
    let a = symbol_for(&ir, b"a");
    let b = symbol_for(&ir, b"b");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let local_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(100)))
        .expect("registered local thunk allocates");
    let mut roots = [local_source];

    let value = evaluator
        .with_transient_value_stack_roots(ir.root, span, &mut roots, |eval| eval.eval_root())
        .expect("GC-stress lambda default attrset evaluates");

    assert!(evaluator.transient_value_stack_roots().is_empty());
    assert!(
        roots[0].raw_eq(local_source),
        "registered root relocated while lambda default binding assembly was evaluated"
    );
    assert_eq!(value.tag(), ValueTag::Attrs);
    let (a_value, b_value) = {
        let attrs = evaluator
            .heap()
            .get_attrs(value)
            .expect("root attrset is heap-owned");
        (
            attrs.get(a).expect("a exists"),
            attrs.get(b).expect("b exists"),
        )
    };
    for value in [a_value, b_value] {
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap()
            .get_thunk(value)
            .expect("default value is a heap-owned thunk");
        assert!(thunk.env().is_some_and(|env| !env.frames().is_empty()));
    }
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert_eq!(
        heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values),
        0
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
fn gc_stress_attrs_accumulator_allocation_node_clears_after_binding_error() {
    let span = Span::new(0, 1);
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let b = symbols.intern(b"b").expect("b interns");
    let body = IrId::new(0);
    let first_value = IrId::new(1);
    let error_value = IrId::new(2);
    let root = IrId::new(3);
    let ir = manual_ir_with_attr_tables(
        root,
        vec![
            pure_node(IrKind::Int, span, IrData::Int(7)),
            pure_node(IrKind::ThunkAlloc, span, IrData::Node(body)),
            pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 }),
            pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 2),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            ),
        ],
        symbols,
        vec![
            IrBinding {
                key: IrAttrPathSegment::Static(a),
                position: None,
                value: first_value,
            },
            IrBinding {
                key: IrAttrPathSegment::Static(b),
                position: None,
                value: error_value,
            },
        ],
        vec![IrShape::new(vec![a, b].into_boxed_slice())],
    );
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );

    let error = evaluator
        .eval_root()
        .expect_err("invalid attr binding reports evaluation error");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::MissingEnvironment { id: error_value }
    );
    let thunk_values = heap_record_values_with_tag(evaluator.heap(), ValueTag::Thunk);
    assert!(heap_record_forwarding_slot_count(evaluator.heap(), &thunk_values) >= 1);
    assert_eq!(evaluator.active_root_eval_node, None);
    assert_eq!(evaluator.active_gc_stress_accumulator_allocation_node, None);
    assert_eq!(evaluator.active_composite_accumulator_depth, 0);
    assert!(evaluator.transient_value_stack_roots().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
        eval_list_string_bytes_with_options(
            "builtins.attrNames builtins.builtins",
            options.clone()
        ),
        fixture,
    );

    let outcome =
        eval_whnf_owned_with_options(&lower("builtins"), options).expect("builtins evaluates");
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("builtins metadata exists");
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
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
