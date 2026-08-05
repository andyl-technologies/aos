//! Tree-walk evaluator tests: options.

// Many GC-stress tests here are gated off under the Candidate-C variant
// (record placement outside the single reservation), leaving shared helpers
// unused on that carrier only; the baseline still uses them.
#![cfg_attr(feature = "candidate_c_value", allow(dead_code))]

use super::*;
mod part_1;
mod part_10;
mod part_11;
mod part_12;
mod part_2;
mod part_3;
mod part_4;
mod part_5;
mod part_6;
mod part_7;
mod part_8;
mod part_9;
use crate::attrs::repr::AttrSetReprKind;
use crate::eval::heap::EvalThunkForceStorageMode;
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
use serde_json::Number as JsonNumber;

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

fn apply2_thunk_values(evaluator: &TreeWalk, value: Value) -> (Value, Value, Value) {
    let thunk = evaluator
        .heap()
        .get_thunk(value)
        .expect("apply2 result is a thunk");
    let EvalThunkKind::Apply2(apply2) = thunk.kind() else {
        panic!("result is an apply2 thunk");
    };
    (
        apply2.function_value,
        apply2.first_argument_value,
        apply2.second_argument_value,
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
