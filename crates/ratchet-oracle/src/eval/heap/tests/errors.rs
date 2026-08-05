//! Error-path coverage for heap pointer and record validation.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
