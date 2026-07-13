//! Evaluator-heap unit tests, part 5 of 16 (RFC-0007 §2 split, #9).
//!
//! Move-only item-boundary split of the `tests.rs` inline body; each
//! test keeps its `#[cfg]`/doc prefix. No test changed.

#![allow(unused_imports)]

use super::super::*;
use super::*;


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn attr_values_with_different_projected_shape_metadata_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs_with_projected_shape_metadata(
            42,
            AttrSetReprKind::Flat,
            Some(ShapeId::new(1)),
            attrs_with_one_entry(),
        )
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs_with_projected_shape_metadata(
            42,
            AttrSetReprKind::Flat,
            Some(ShapeId::new(2)),
            attrs_with_one_entry(),
        )
        .expect("second attrs allocate");

    assert!(!first.raw_eq(second));
    assert_eq!(heap.len(), 2);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_filters_inline_values_and_walks_typed_fields() {
    let mut symbols = SymbolTable::new();
    let child_key = symbols.intern(b"child").expect("child symbol interns");
    let inline_key = symbols.intern(b"inline").expect("inline symbol interns");
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let leaf = heap
        .alloc_string(NixString::from_bytes(b"leaf".to_vec()))
        .expect("leaf string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), leaf]))
        .expect("list allocates");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(inline_key, Value::bool(true)),
            AttrEntry::new(child_key, list),
        ],
        &symbols,
    )
    .expect("attrs build");
    let root = heap.alloc_attrs(17, attrs).expect("attrs allocate");
    let mut roots = EvalRootSet::new();

    assert!(
        !roots
            .try_push_value_stack(0, Value::int(99))
            .expect("inline root ignored")
    );
    assert!(
        !roots
            .try_push_stack_map(1, 2, StackMapSlot::Stack { offset: -16 }, Value::null(),)
            .expect("inline stack-map value ignored")
    );
    assert!(
        roots
            .try_push_value_stack(1, root)
            .expect("heap root records")
    );

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");

    assert_eq!(scan.roots().len(), 1);
    assert_eq!(scan.objects().len(), 3);
    assert!(scan.objects()[0].value().raw_eq(root));
    assert!(scan.objects()[1].value().raw_eq(list));
    assert!(scan.objects()[2].value().raw_eq(leaf));

    let root_edges = object_for(&scan, root).edges();
    assert_eq!(root_edges.len(), 1);
    assert_eq!(
        root_edges[0].source(),
        &HeapEdgeSource::AttrBinding {
            shape: 17,
            slot: 0,
            key: child_key,
        }
    );
    assert!(root_edges[0].value().raw_eq(list));

    let list_edges = object_for(&scan, list).edges();
    assert_eq!(list_edges.len(), 1);
    assert_eq!(
        list_edges[0].source(),
        &HeapEdgeSource::ListElement { index: 1 }
    );
    assert!(list_edges[0].value().raw_eq(leaf));
    assert!(object_for(&scan, leaf).edges().is_empty());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_root_scan_pairs_poll_request_with_precise_heap_graph() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let leaf = heap
        .alloc_string(NixString::from_bytes(b"leaf".to_vec()))
        .expect("leaf string allocates");
    let root = heap
        .alloc_list(NixList::new(vec![Value::int(1), leaf]))
        .expect("list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("heap root records");

    let snapshot = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");

    assert_eq!(snapshot.poll(), poll);
    assert_eq!(snapshot.heap_records(), heap.len());
    assert_eq!(
        snapshot.allocation_safepoints(),
        heap.allocation_safepoints()
    );
    assert_eq!(
        snapshot.permanent_allocation_safepoints(),
        heap.permanent_allocation_safepoints()
    );
    assert_eq!(snapshot.scan().roots().len(), 1);
    assert_eq!(snapshot.scan().objects().len(), 2);
    assert!(snapshot.scan().objects()[0].value().raw_eq(root));
    assert!(snapshot.scan().objects()[1].value().raw_eq(leaf));
    assert_eq!(
        snapshot.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert_eq!(
        snapshot.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
}
