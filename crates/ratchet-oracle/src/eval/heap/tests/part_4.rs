//! Evaluator-heap unit tests, part 4 of 16 (RFC-0007 §2 split, #9).
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, second),
        HeapAllocationDomain::PermanentShared
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn permanent_container_records_can_reference_worker_domain_children() {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"child").expect("child symbol interns");
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let list = heap
        .alloc_list(NixList::new(vec![thunk]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(
            7,
            FlatAttrs::new(vec![AttrEntry::new(key, thunk)], &symbols).expect("attrs build"),
        )
        .expect("attrs allocate");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, list)
        .expect("list root records");
    roots
        .try_push_value_stack(1, attrs)
        .expect("attrs root records");

    assert_eq!(
        allocation_domain(&heap, thunk),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        allocation_domain(&heap, list),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        allocation_domain(&heap, attrs),
        HeapAllocationDomain::PermanentShared
    );

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let list_edges = object_for(&scan, list).edges();
    assert_eq!(list_edges.len(), 1);
    assert_eq!(
        list_edges[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert!(list_edges[0].value().raw_eq(thunk));

    let attrs_edges = object_for(&scan, attrs).edges();
    assert_eq!(attrs_edges.len(), 1);
    assert_eq!(
        attrs_edges[0].source(),
        &HeapEdgeSource::AttrBinding {
            shape: 7,
            slot: 0,
            key,
        }
    );
    assert!(attrs_edges[0].value().raw_eq(thunk));
    assert!(object_for(&scan, thunk).edges().is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::Worker
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::Worker
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::Worker
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    assert!(
        heap.records
            .iter()
            .all(|record| record.allocation_domain == HeapAllocationDomain::Worker),
        "effectful heap records must stay in the worker allocation domain"
    );
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    let metadata = heap
        .get_attrs_metadata(value)
        .expect("attr metadata exists");
    assert_eq!(metadata.shape(), 42);
    assert_eq!(metadata.projected_shape(), None);
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn allocates_attr_values_with_explicit_repr_metadata() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_attrs_with_repr_metadata(42, AttrSetReprKind::Hamt, attrs_with_one_entry())
        .expect("attrs allocate");

    let metadata = heap
        .get_attrs_metadata(value)
        .expect("attr metadata exists");
    assert_eq!(metadata.shape(), 42);
    assert_eq!(metadata.projected_shape(), None);
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn allocates_attr_values_with_projected_shape_metadata() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_attrs_with_projected_shape_metadata(
            42,
            AttrSetReprKind::Flat,
            Some(ShapeId::new(7)),
            attrs_with_one_entry(),
        )
        .expect("attrs allocate");

    let metadata = heap
        .get_attrs_metadata(value)
        .expect("attr metadata exists");
    assert_eq!(metadata.shape(), 42);
    assert_eq!(metadata.projected_shape(), Some(ShapeId::new(7)));
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn attr_values_with_different_repr_metadata_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(42, attrs_with_one_entry())
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs_with_repr_metadata(42, AttrSetReprKind::Hamt, attrs_with_one_entry())
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
    assert_eq!(
        heap.get_attrs_metadata(first)
            .expect("first metadata exists")
            .repr(),
        AttrSetReprKind::Flat
    );
    assert_eq!(
        heap.get_attrs_metadata(second)
            .expect("second metadata exists")
            .repr(),
        AttrSetReprKind::Hamt
    );
}
