//! Unit tests for the typed evaluator heap registry.

use super::super::ThunkState;
use super::*;
use crate::attrs::AttrEntry;
use crate::runtime::builtins::lookup_builtin;
use crate::string::{ContextElement, StringContext};
use crate::syntax::SymbolTable;

fn attrs_with_one_entry() -> FlatAttrs {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    FlatAttrs::new(vec![AttrEntry::new(key, Value::int(7))], &symbols).expect("attrset builds")
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

#[test]
fn reports_unknown_string_pointers() {
    let heap = EvalHeap::new();
    let ptr = NonNull::<HeapObject>::dangling();
    let value = Value::string(ptr).expect("dangling pointer is aligned");
    let error = heap
        .get_string(value)
        .expect_err("pointer does not belong to heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::String, ptr));
}

#[test]
fn reports_unknown_path_pointers() {
    let heap = EvalHeap::new();
    let ptr = NonNull::<HeapObject>::dangling();
    let value = Value::path(ptr).expect("dangling pointer is aligned");
    let error = heap
        .get_path(value)
        .expect_err("pointer does not belong to heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Path, ptr));
}

#[test]
fn reports_unknown_list_pointers() {
    let heap = EvalHeap::new();
    let ptr = NonNull::<HeapObject>::dangling();
    let value = Value::list(ptr).expect("dangling pointer is aligned");
    let error = heap
        .get_list(value)
        .expect_err("pointer does not belong to heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::List, ptr));
}

#[test]
fn reports_unknown_thunk_pointers() {
    let heap = EvalHeap::new();
    let ptr = NonNull::<HeapObject>::dangling();
    let value = Value::thunk(ptr).expect("dangling pointer is aligned");
    let error = heap
        .get_thunk(value)
        .expect_err("pointer does not belong to heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Thunk, ptr));
}

#[test]
fn reports_unknown_lambda_pointers() {
    let heap = EvalHeap::new();
    let ptr = NonNull::<HeapObject>::dangling();
    let value = Value::lambda(ptr).expect("dangling pointer is aligned");
    let error = heap
        .get_lambda(value)
        .expect_err("pointer does not belong to heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Lambda, ptr));
}

#[test]
fn reports_unknown_primop_pointers() {
    let heap = EvalHeap::new();
    let ptr = NonNull::<HeapObject>::dangling();
    let value = Value::primop(ptr).expect("dangling pointer is aligned");
    let error = heap
        .get_primop(value)
        .expect_err("pointer does not belong to heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Primop, ptr));
}

#[test]
fn reports_unknown_attrs_pointers() {
    let heap = EvalHeap::new();
    let ptr = NonNull::<HeapObject>::dangling();
    let value = Value::attrs(ptr).expect("dangling pointer is aligned");
    let error = heap
        .get_attrs(value)
        .expect_err("pointer does not belong to heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Attrs, ptr));
}

#[test]
fn reports_heap_record_type_mismatches() {
    let mut heap = EvalHeap::new();
    let list = heap.alloc_list(NixList::empty()).expect("list allocates");
    let list_ptr = list.as_list_ptr().expect("list pointer");
    let mislabeled_string = Value::string(list_ptr).expect("same pointer can carry string tag");

    let error = heap
        .get_string(mislabeled_string)
        .expect_err("record is not a string");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, list_ptr)
    );
    let mislabeled_path = Value::path(list_ptr).expect("same pointer can carry path tag");

    let error = heap
        .get_path(mislabeled_path)
        .expect_err("record is not a path");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::Path, ValueTag::List, list_ptr)
    );

    let string = heap
        .alloc_string(NixString::from_bytes(b"payload".to_vec()))
        .expect("string allocates");
    let string_ptr = string.as_string_ptr().expect("string pointer");
    let mislabeled_list = Value::list(string_ptr).expect("same pointer can carry list tag");

    let error = heap
        .get_list(mislabeled_list)
        .expect_err("record is not a list");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::List, ValueTag::String, string_ptr)
    );
    let mislabeled_thunk = Value::thunk(string_ptr).expect("same pointer can carry thunk tag");

    let error = heap
        .get_thunk(mislabeled_thunk)
        .expect_err("record is not a thunk");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::Thunk, ValueTag::String, string_ptr)
    );
    let mislabeled_lambda = Value::lambda(string_ptr).expect("same pointer can carry lambda tag");

    let error = heap
        .get_lambda(mislabeled_lambda)
        .expect_err("record is not a lambda");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::Lambda, ValueTag::String, string_ptr)
    );
    let mislabeled_primop = Value::primop(string_ptr).expect("same pointer can carry primop tag");

    let error = heap
        .get_primop(mislabeled_primop)
        .expect_err("record is not a primop");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::Primop, ValueTag::String, string_ptr)
    );
    let mislabeled_attrs = Value::attrs(string_ptr).expect("same pointer can carry attrs tag");

    let error = heap
        .get_attrs(mislabeled_attrs)
        .expect_err("record is not an attrset");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::Attrs, ValueTag::String, string_ptr)
    );
    let mislabeled_path = Value::path(string_ptr).expect("same pointer can carry path tag");

    let error = heap
        .get_path(mislabeled_path)
        .expect_err("record is not a path");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::Path, ValueTag::String, string_ptr)
    );

    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(0)))
        .expect("thunk allocates");
    let thunk_ptr = thunk.as_thunk_ptr().expect("thunk pointer");
    let mislabeled_list = Value::list(thunk_ptr).expect("same pointer can carry list tag");

    let error = heap
        .get_list(mislabeled_list)
        .expect_err("record is not a list");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::List, ValueTag::Thunk, thunk_ptr)
    );

    let lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(1),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lambda allocates");
    let lambda_ptr = lambda.as_lambda_ptr().expect("lambda pointer");
    let mislabeled_string = Value::string(lambda_ptr).expect("same pointer can carry string tag");

    let error = heap
        .get_string(mislabeled_string)
        .expect_err("record is not a string");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::Lambda, lambda_ptr)
    );
}

#[test]
fn propagates_invalid_initial_arena_chunk_size() {
    let error = EvalHeap::with_initial_chunk_bytes(0).expect_err("zero chunk size is invalid");

    assert_eq!(
        error,
        EvalHeapError::Arena(ArenaError::InvalidChunkSize { chunk_bytes: 0 })
    );
}
