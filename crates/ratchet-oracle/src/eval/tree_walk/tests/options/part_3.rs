//! Split-out tests (part_3). See parent module.

use super::*;

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
