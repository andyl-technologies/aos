//! Unit tests for the typed evaluator heap registry.

use super::super::ThunkState;
use super::*;
use crate::attrs::{AttrEntry, AttrPosition};
use crate::runtime::builtins::lookup_builtin;
use crate::string::{ContextElement, StringContext};
use crate::syntax::SymbolTable;

mod errors;

fn attrs_with_one_entry() -> FlatAttrs {
    attrs_with_value(Value::int(7))
}

fn attrs_with_value(value: Value) -> FlatAttrs {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    FlatAttrs::new(vec![AttrEntry::new(key, value)], &symbols).expect("attrset builds")
}

fn attrs_with_ordered_entries(first: &[u8], second: &[u8]) -> FlatAttrs {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a symbol interns");
    let b = symbols.intern(b"b").expect("b symbol interns");
    let key = |name: &[u8]| match name {
        b"a" => a,
        b"b" => b,
        _ => unreachable!("test helper accepts only a/b keys"),
    };
    FlatAttrs::new(
        vec![
            AttrEntry::new(key(first), Value::int(i64::from(first[0]))),
            AttrEntry::new(key(second), Value::int(i64::from(second[0]))),
        ],
        &symbols,
    )
    .expect("attrset builds")
}

#[test]
fn allocates_string_values_and_recovers_contents() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(64).expect("heap creates");
    let value = heap
        .alloc_string(NixString::from_bytes(b"hello".to_vec()))
        .expect("string allocates");

    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_string(value).expect("string exists").bytes(),
        b"hello"
    );
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn multiple_string_values_keep_distinct_heap_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(b"first".to_vec()))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(b"second".to_vec()))
        .expect("second string allocates");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
    assert_eq!(
        heap.get_string(first).expect("first exists").bytes(),
        b"first"
    );
    assert_eq!(
        heap.get_string(second).expect("second exists").bytes(),
        b"second"
    );
}

#[test]
fn identical_string_values_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_string(second)
            .expect("second string exists")
            .bytes(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg"
    );
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn hash_consed_heap_records_share_cached_captured_value_hashes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let hash = ValueHash::from_canonical_value_hash(crate::cache::DurableBlake3Hash::for_bytes(
        b"captured string",
    ));

    assert!(first.raw_eq(second));
    assert_eq!(heap.cached_captured_value_hash(first), Ok(None));
    assert_eq!(heap.cached_captured_value_hash(second), Ok(None));

    heap.cache_captured_value_hash(first, hash)
        .expect("captured hash caches");

    assert_eq!(heap.cached_captured_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_captured_value_hash(second), Ok(Some(hash)));
    assert_eq!(heap.cached_captured_value_hash(list), Ok(None));
}

#[test]
fn hash_consed_heap_records_share_cached_value_hashes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let hash = ValueHash::from_context_free_string_bytes(
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg",
    );

    assert!(first.raw_eq(second));
    assert_eq!(heap.cached_value_hash(first), Ok(None));
    assert_eq!(heap.cached_value_hash(second), Ok(None));

    assert_eq!(
        heap.cache_value_hash(first, hash)
            .expect("value hash caches"),
        HeapValueHashCacheUpdate::Inserted
    );

    assert_eq!(heap.cached_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(second), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(list), Ok(None));

    assert_eq!(
        heap.cache_value_hash(second, hash)
            .expect("alias accepts same value hash"),
        HeapValueHashCacheUpdate::AlreadyPresent
    );
    let other_hash = ValueHash::from_context_free_string_bytes(b"other");
    assert_eq!(
        heap.cache_value_hash(second, other_hash),
        Err(EvalHeapError::ValueHashMismatch {
            existing: hash,
            attempted: other_hash,
        })
    );
    assert_eq!(heap.cached_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(second), Ok(Some(hash)));
}

#[test]
fn cached_value_hashes_reject_mismatched_rewrites() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let value = heap
        .alloc_string(NixString::from_bytes(b"value".to_vec()))
        .expect("string allocates");
    let first_hash = ValueHash::from_context_free_string_bytes(b"value");
    let second_hash = ValueHash::from_context_free_string_bytes(b"other");

    assert_eq!(
        heap.cache_value_hash(value, first_hash)
            .expect("first hash caches"),
        HeapValueHashCacheUpdate::Inserted
    );
    assert_eq!(
        heap.cache_value_hash(value, first_hash)
            .expect("same hash is accepted"),
        HeapValueHashCacheUpdate::AlreadyPresent
    );
    assert_eq!(
        heap.cache_value_hash(value, second_hash),
        Err(EvalHeapError::ValueHashMismatch {
            existing: first_hash,
            attempted: second_hash,
        })
    );
    assert_eq!(heap.cached_value_hash(value), Ok(Some(first_hash)));
}

#[test]
fn captured_value_hash_cache_rejects_unsupported_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let hash = ValueHash::from_canonical_value_hash(crate::cache::DurableBlake3Hash::for_bytes(
        b"captured",
    ));
    let expected_int = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Int,
    });
    let expected_thunk = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Thunk,
    });

    assert_eq!(
        heap.cached_captured_value_hash(Value::int(1)),
        Err(expected_int.clone())
    );
    assert_eq!(
        heap.cache_captured_value_hash(Value::int(1), hash),
        Err(expected_int)
    );
    assert_eq!(
        heap.cached_captured_value_hash(thunk),
        Err(expected_thunk.clone())
    );
    assert_eq!(
        heap.cache_captured_value_hash(thunk, hash),
        Err(expected_thunk)
    );
}

#[test]
fn value_hash_cache_rejects_unsupported_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let hash = ValueHash::from_context_free_string_bytes(b"value");
    let expected_int = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Int,
    });
    let expected_thunk = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Thunk,
    });

    assert_eq!(
        heap.cached_value_hash(Value::int(1)),
        Err(expected_int.clone())
    );
    assert_eq!(
        heap.cache_value_hash(Value::int(1), hash),
        Err(expected_int)
    );
    assert_eq!(heap.cached_value_hash(thunk), Err(expected_thunk.clone()));
    assert_eq!(heap.cache_value_hash(thunk, hash), Err(expected_thunk));
}

#[test]
fn captured_value_hash_cache_validates_heap_ownership_and_record_type() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap.alloc_list(NixList::empty()).expect("list allocates");
    let list_ptr = list.as_list_ptr().expect("list pointer");
    let mislabeled_string = Value::string(list_ptr).expect("same pointer can carry string tag");
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
        .expect("foreign string allocates");
    let foreign_ptr = foreign.as_string_ptr().expect("foreign pointer");
    let hash = ValueHash::from_canonical_value_hash(crate::cache::DurableBlake3Hash::for_bytes(
        b"captured",
    ));
    let mismatch = EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, list_ptr);
    let unknown = EvalHeapError::unknown(ValueTag::String, foreign_ptr);

    assert_eq!(
        heap.cached_captured_value_hash(mislabeled_string),
        Err(mismatch.clone())
    );
    assert_eq!(
        heap.cache_captured_value_hash(mislabeled_string, hash),
        Err(mismatch)
    );
    assert_eq!(
        heap.cached_captured_value_hash(foreign),
        Err(unknown.clone())
    );
    assert_eq!(heap.cache_captured_value_hash(foreign, hash), Err(unknown));
}

#[test]
fn value_hash_cache_validates_heap_ownership_and_record_type() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap.alloc_list(NixList::empty()).expect("list allocates");
    let list_ptr = list.as_list_ptr().expect("list pointer");
    let mislabeled_string = Value::string(list_ptr).expect("same pointer can carry string tag");
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
        .expect("foreign string allocates");
    let foreign_ptr = foreign.as_string_ptr().expect("foreign pointer");
    let hash = ValueHash::from_context_free_string_bytes(b"value");
    let mismatch = EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, list_ptr);
    let unknown = EvalHeapError::unknown(ValueTag::String, foreign_ptr);

    assert_eq!(
        heap.cached_value_hash(mislabeled_string),
        Err(mismatch.clone())
    );
    assert_eq!(
        heap.cache_value_hash(mislabeled_string, hash),
        Err(mismatch)
    );
    assert_eq!(heap.cached_value_hash(foreign), Err(unknown.clone()));
    assert_eq!(heap.cache_value_hash(foreign, hash), Err(unknown));
}

#[test]
fn identical_string_bytes_with_different_contexts_do_not_collapse() {
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/source".to_vec()).expect("context builds"),
    )
    .expect("singleton context allocates");
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let context_free = heap
        .alloc_string(NixString::from_bytes(b"/nix/store/pkg".to_vec()))
        .expect("context-free string allocates");
    let context_bearing = heap
        .alloc_string(NixString::new(b"/nix/store/pkg".to_vec(), context))
        .expect("context-bearing string allocates");

    assert_eq!(context_free.tag(), ValueTag::String);
    assert_eq!(context_bearing.tag(), ValueTag::String);
    assert_ne!(context_free.payload_bits(), context_bearing.payload_bits());
    assert_eq!(heap.len(), 2);
    assert!(
        !heap
            .get_string(context_free)
            .expect("context-free string exists")
            .has_context()
    );
    assert!(
        heap.get_string(context_bearing)
            .expect("context-bearing string exists")
            .has_context()
    );
}

#[test]
fn allocates_path_values_and_recovers_bytes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_path(NixString::from_bytes(b"/tmp/source".to_vec()))
        .expect("path allocates");

    assert_eq!(value.tag(), ValueTag::Path);
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_path(value).expect("path exists").bytes(),
        b"/tmp/source"
    );
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn identical_path_values_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_path(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec(),
        ))
        .expect("first path allocates");
    let second = heap
        .alloc_path(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec(),
        ))
        .expect("second path allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_path(second).expect("second path exists").bytes(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source"
    );
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn string_and_path_cons_tables_are_separate() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let bytes = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec();
    let string = heap
        .alloc_string(NixString::from_bytes(bytes.clone()))
        .expect("string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(bytes))
        .expect("path allocates");

    assert_eq!(string.tag(), ValueTag::String);
    assert_eq!(path.tag(), ValueTag::Path);
    assert_ne!(string.payload_bits(), path.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn allocates_list_values_and_recovers_spine() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");

    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(heap.len(), 1);
    let list = heap.get_list(value).expect("list exists");
    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first element").as_int(), Ok(1));
    assert_eq!(list.get(1).expect("second element").as_bool(), Ok(true));
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn identical_list_values_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("second list allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    let list = heap.get_list(second).expect("second list exists");
    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first element").as_int(), Ok(1));
    assert_eq!(list.get(1).expect("second element").as_bool(), Ok(true));
}

#[test]
fn list_values_with_different_elements_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![Value::int(2)]))
        .expect("second list allocates");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn list_values_with_same_thunk_identity_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let first = heap
        .alloc_list(NixList::new(vec![thunk]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![thunk]))
        .expect("second list allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 2);
}

#[test]
fn list_values_with_distinct_thunk_identities_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("first thunk allocates");
    let second_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("second thunk allocates");
    let first = heap
        .alloc_list(NixList::new(vec![first_thunk]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![second_thunk]))
        .expect("second list allocates");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 4);
}

#[test]
fn allocates_thunk_values_and_recovers_body() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let body = IrId::new(7);
    let value = heap
        .alloc_thunk(EvalThunk::new(body))
        .expect("thunk allocates");

    assert_eq!(value.tag(), ValueTag::Thunk);
    assert_eq!(heap.len(), 1);
    let thunk = heap.get_thunk(value).expect("thunk exists");
    assert_eq!(thunk.body(), Some(body));
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn allocates_apply_thunk_values_and_recovers_work() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(1),
            Span::new(0, 1),
            Value::int(7),
            EvalModuleId::ROOT,
            IrId::new(2),
            Value::bool(true),
        ))
        .expect("thunk allocates");

    assert_eq!(value.tag(), ValueTag::Thunk);
    assert_eq!(heap.len(), 1);
    let thunk = heap.get_thunk(value).expect("thunk exists");
    assert_eq!(thunk.body(), None);
    assert!(matches!(thunk.kind(), EvalThunkKind::Apply { .. }));
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn allocates_lambda_values_and_recovers_closure() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let pattern = IrId::new(3);
    let body = IrId::new(7);
    let frame = FrameId::new(1);
    let value = heap
        .alloc_lambda(EvalLambda::new(pattern, body, frame, EvalEnv::default()))
        .expect("lambda allocates");

    assert_eq!(value.tag(), ValueTag::Lambda);
    assert_eq!(heap.len(), 1);
    let lambda = heap.get_lambda(value).expect("lambda exists");
    assert_eq!(lambda.pattern(), pattern);
    assert_eq!(lambda.body(), body);
    assert_eq!(lambda.frame(), frame);
    assert!(lambda.env().frames().is_empty());
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn allocates_primop_values_and_recovers_record() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let argument = EvalPrimOpArg::new(IrId::new(2), Span::new(4, 8), Value::int(3));
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![argument],
        ))
        .expect("primop allocates");

    assert_eq!(value.tag(), ValueTag::Primop);
    assert_eq!(heap.len(), 1);
    let primop = heap.get_primop(value).expect("primop exists");
    assert_eq!(primop.builtin(), Some(builtin));
    assert_eq!(primop.symbol(), symbol);
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].id(), IrId::new(2));
    assert_eq!(primop.args()[0].span(), Span::new(4, 8));
    assert!(primop.args()[0].value().raw_eq(Value::int(3)));
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn lambdas_primops_and_thunks_are_not_hash_consed() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let argument = EvalPrimOpArg::new(IrId::new(2), Span::new(4, 8), Value::int(3));
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");

    let first_lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(7),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("first lambda allocates");
    let second_lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(7),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("second lambda allocates");
    let first_primop = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![argument],
        ))
        .expect("first primop allocates");
    let second_primop = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![argument],
        ))
        .expect("second primop allocates");
    let first_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("first thunk allocates");
    let second_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("second thunk allocates");

    assert_ne!(first_lambda.payload_bits(), second_lambda.payload_bits());
    assert_ne!(first_primop.payload_bits(), second_primop.payload_bits());
    assert_ne!(first_thunk.payload_bits(), second_thunk.payload_bits());
    assert_eq!(heap.len(), 6);
    assert!(
        heap.records
            .iter()
            .all(|record| record.structural_hash.is_none()),
        "effectful heap records must not participate in structural consing"
    );
}

#[test]
fn public_primop_constructors_keep_symbol_only_records() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let argument = EvalPrimOpArg::new(IrId::new(2), Span::new(4, 8), Value::int(3));

    let empty = EvalPrimOp::new(symbol);
    assert_eq!(empty.builtin(), None);
    assert_eq!(empty.symbol(), symbol);
    assert!(empty.args().is_empty());

    let partial = EvalPrimOp::with_args(symbol, vec![argument]);
    assert_eq!(partial.builtin(), None);
    assert_eq!(partial.symbol(), symbol);
    assert_eq!(partial.args().len(), 1);
}

#[test]
fn allocates_attr_values_and_recovers_entries() {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let attrs =
        FlatAttrs::new(vec![AttrEntry::new(key, Value::int(7))], &symbols).expect("attrs build");
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap.alloc_attrs(42, attrs).expect("attrs allocate");

    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(heap.len(), 1);
    let attrs = heap.get_attrs(value).expect("attrs exist");
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs.get(key).expect("name exists").as_int(), Ok(7));
    assert_eq!(heap.arena_stats().chunks, 1);
}

#[test]
fn identical_attr_values_with_same_shape_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(42, attrs_with_one_entry())
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(42, attrs_with_one_entry())
        .expect("second attrs allocate");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    let attrs = heap.get_attrs(second).expect("second attrs exist");
    assert_eq!(attrs.len(), 1);
}

#[test]
fn attr_values_with_different_shapes_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(1, attrs_with_one_entry())
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(2, attrs_with_one_entry())
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn attr_values_with_different_binding_values_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let first = heap
        .alloc_attrs(0, attrs_with_value(Value::int(7)))
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(0, attrs_with_value(Value::int(8)))
        .expect("second attrs allocate");
    assert_ne!(first.payload_bits(), second.payload_bits());

    let first_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("first thunk allocates");
    let second_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("second thunk allocates");
    let first_attrs = heap
        .alloc_attrs(0, attrs_with_value(first_thunk))
        .expect("first thunk attrs allocate");
    let second_attrs = heap
        .alloc_attrs(0, attrs_with_value(second_thunk))
        .expect("second thunk attrs allocate");

    assert_ne!(first_attrs.payload_bits(), second_attrs.payload_bits());
    assert_eq!(heap.len(), 6);
}

#[test]
fn attr_values_with_different_source_order_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_attrs(0, attrs_with_ordered_entries(b"a", b"b"))
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(0, attrs_with_ordered_entries(b"b", b"a"))
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn attr_values_with_different_positions_do_not_collapse() {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let first_attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            key,
            Value::int(7),
            AttrPosition::new(0, Span::new(0, 1)),
        )],
        &symbols,
    )
    .expect("first attrs build");
    let second_attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            key,
            Value::int(7),
            AttrPosition::new(0, Span::new(1, 2)),
        )],
        &symbols,
    )
    .expect("second attrs build");
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(0, first_attrs)
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(0, second_attrs)
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn mixed_heap_object_types_keep_distinct_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"name".to_vec()))
        .expect("string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(b"/tmp/name".to_vec()))
        .expect("path allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(7)]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(9, attrs_with_one_entry())
        .expect("attrs allocate");
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let primop = heap
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("primop allocates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("thunk allocates");

    assert_ne!(string.payload_bits(), path.payload_bits());
    assert_ne!(string.payload_bits(), list.payload_bits());
    assert_ne!(string.payload_bits(), attrs.payload_bits());
    assert_ne!(string.payload_bits(), primop.payload_bits());
    assert_ne!(string.payload_bits(), thunk.payload_bits());
    assert_ne!(path.payload_bits(), list.payload_bits());
    assert_ne!(path.payload_bits(), attrs.payload_bits());
    assert_ne!(path.payload_bits(), primop.payload_bits());
    assert_ne!(path.payload_bits(), thunk.payload_bits());
    assert_ne!(list.payload_bits(), attrs.payload_bits());
    assert_ne!(list.payload_bits(), primop.payload_bits());
    assert_ne!(list.payload_bits(), thunk.payload_bits());
    assert_ne!(attrs.payload_bits(), primop.payload_bits());
    assert_ne!(attrs.payload_bits(), thunk.payload_bits());
    assert_ne!(primop.payload_bits(), thunk.payload_bits());
    assert_eq!(heap.len(), 6);
    assert_eq!(
        heap.get_string(string).expect("string exists").bytes(),
        b"name"
    );
    assert_eq!(
        heap.get_path(path).expect("path exists").bytes(),
        b"/tmp/name"
    );
    assert_eq!(
        heap.get_list(list)
            .expect("list exists")
            .get(0)
            .expect("first element")
            .as_int(),
        Ok(7)
    );
    assert_eq!(heap.get_attrs(attrs).expect("attrs exist").len(), 1);
    assert_eq!(
        heap.get_primop(primop).expect("primop exists").symbol(),
        symbol
    );
    assert_eq!(
        heap.get_thunk(thunk).expect("thunk exists").body(),
        Some(IrId::new(3))
    );
}

#[test]
fn preserves_context_bearing_strings() {
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/source".to_vec()).expect("context builds"),
    )
    .expect("singleton context allocates");
    let string = NixString::new(b"payload".to_vec(), context);
    let mut heap = EvalHeap::new();
    let value = heap.alloc_string(string).expect("string allocates");
    let stored = heap.get_string(value).expect("string exists");

    assert_eq!(stored.bytes(), b"payload");
    assert!(stored.has_context());
    assert_eq!(stored.context().len(), 1);
    assert_eq!(stored.context().elements()[0].path(), b"/nix/store/source");
}

#[test]
fn rejects_string_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
        .expect("foreign string allocates");
    let ptr = foreign.as_string_ptr().expect("foreign is a string");
    let error = heap
        .get_string(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::String, ptr));
}

#[test]
fn rejects_path_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_path(NixString::from_bytes(b"/tmp/foreign".to_vec()))
        .expect("foreign path allocates");
    let ptr = foreign.as_path_ptr().expect("foreign is a path");
    let error = heap
        .get_path(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Path, ptr));
}

#[test]
fn rejects_list_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("foreign list allocates");
    let ptr = foreign.as_list_ptr().expect("foreign is a list");
    let error = heap
        .get_list(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::List, ptr));
}

#[test]
fn rejects_attr_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_attrs(0, attrs_with_one_entry())
        .expect("foreign attrs allocate");
    let ptr = foreign.as_attrs_ptr().expect("foreign is an attrset");
    let error = heap
        .get_attrs(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Attrs, ptr));
}

#[test]
fn rejects_thunk_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("foreign thunk allocates");
    let ptr = foreign.as_thunk_ptr().expect("foreign is a thunk");
    let error = heap
        .get_thunk(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Thunk, ptr));
}

#[test]
fn rejects_primop_values_from_another_live_heap() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("foreign primop allocates");
    let ptr = foreign.as_primop_ptr().expect("foreign is a primop");
    let error = heap
        .get_primop(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Primop, ptr));
}

#[test]
fn rejects_wrong_value_tags_for_string_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_string(Value::int(1))
        .expect_err("integer is not a string");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "string",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_path_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_path(Value::int(1))
        .expect_err("integer is not a path");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "path",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_list_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_list(Value::int(1))
        .expect_err("integer is not a list");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "list",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_thunk_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_thunk(Value::int(1))
        .expect_err("integer is not a thunk");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "thunk",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_primop_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_primop(Value::int(1))
        .expect_err("integer is not a primop");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "primop",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_attrs_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_attrs(Value::int(1))
        .expect_err("integer is not an attrset");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "attrs",
            actual: ValueTag::Int,
        })
    );
}
