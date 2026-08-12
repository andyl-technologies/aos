//! Unit tests for the evaluator environment (split from env.rs, §2 cap).

use super::*;

#[test]
fn compact_flat_capture_site_admission_fails_closed_at_each_bit_bound() {
    assert!(EvalFlatCapture::supports_allocation_site(EvalNodeRef::new(
        EvalModuleId::new(4095),
        IrId::new(1_048_575),
    )));
    assert!(!EvalFlatCapture::supports_allocation_site(
        EvalNodeRef::new(EvalModuleId::new(4096), IrId::new(0),)
    ));
    assert!(!EvalFlatCapture::supports_allocation_site(
        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(1_048_576),)
    ));
}

// Baseline two-word AtomicValueCell internals. The `candidate_c_value`
// variant collapses the cell to one word (different fields), so these are
// gated off there; the one-word cell's store/load is exercised end-to-end by
// the K=4 parallel parity battery. See cutover plan §7.
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn atomic_value_cell_roundtrips_every_value_tag() {
    let ptr = NonNull::<HeapObject>::dangling();
    let values = [
        Value::int(-7),
        Value::int(i64::MIN),
        Value::float(f64::from_bits(0x7ff8_0000_0000_0001)),
        Value::float(-0.0),
        Value::bool(true),
        Value::bool(false),
        Value::null(),
        Value::string(ptr).expect("aligned string pointer"),
        Value::path(ptr).expect("aligned path pointer"),
        Value::list(ptr).expect("aligned list pointer"),
        Value::attrs(ptr).expect("aligned attrs pointer"),
        Value::lambda(ptr).expect("aligned lambda pointer"),
        Value::primop(ptr).expect("aligned primop pointer"),
        Value::external(ptr).expect("aligned external pointer"),
        Value::thunk(ptr).expect("aligned thunk pointer"),
    ];

    for value in values {
        let cell = AtomicValueCell::empty();
        assert!(matches!(cell.load(), Ok(None)));
        cell.store(value);
        let loaded = cell
            .load()
            .expect("stored value decodes")
            .expect("stored value is present");
        assert!(loaded.raw_eq(value));
        cell.clear();
        assert!(matches!(cell.load(), Ok(None)));
    }
}

#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn atomic_value_cell_rejects_invalid_encodings() {
    let cell = AtomicValueCell::empty();
    cell.payload.store(0, Ordering::Relaxed);
    cell.tag.store(TAG_STRING, Ordering::Release);
    assert!(matches!(
        cell.load(),
        Err(AtomicValueCellError::InvalidEncoding { .. })
    ));

    cell.payload.store(2, Ordering::Relaxed);
    cell.tag.store(TAG_BOOL, Ordering::Release);
    assert!(matches!(
        cell.load(),
        Err(AtomicValueCellError::InvalidEncoding { .. })
    ));

    cell.payload.store(0, Ordering::Relaxed);
    cell.tag.store(0xdead_beef, Ordering::Release);
    assert!(matches!(
        cell.load(),
        Err(AtomicValueCellError::InvalidEncoding { .. })
    ));
}

#[test]
fn frame_slots_initialize_null_and_roundtrip_set_get() {
    let frame = EvalFrame::new(2).expect("frame allocates");
    assert!(frame.get(0).expect("slot 0 reads").raw_eq(Value::null()));

    frame.set(1, Value::int(42)).expect("slot 1 writes");
    assert!(frame.get(1).expect("slot 1 reads").raw_eq(Value::int(42)));
    assert!(matches!(
        frame.get(2),
        Err(EvalEnvError::SlotOutOfBounds { slot: 2, slots: 2 })
    ));
    assert_eq!(
        frame.set(2, Value::int(1)),
        Err(EvalEnvError::SlotOutOfBounds { slot: 2, slots: 2 })
    );

    let snapshot = frame.slot_values().expect("snapshot copies");
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot[0].raw_eq(Value::null()));
    assert!(snapshot[1].raw_eq(Value::int(42)));
}

#[test]
fn held_test_borrow_rejects_mutation_but_admits_reads() {
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, Value::int(5)).expect("slot writes");

    let borrow = frame.borrow_slots_for_test().expect("test borrow succeeds");
    assert!(borrow[0].raw_eq(Value::int(5)));
    assert_eq!(
        frame.set(0, Value::int(6)),
        Err(EvalEnvError::BorrowConflict)
    );
    assert_eq!(frame.validate_set(0), Err(EvalEnvError::BorrowConflict));
    assert!(
        frame
            .get(0)
            .expect("reads stay admitted")
            .raw_eq(Value::int(5))
    );
    assert!(
        frame
            .slot_values()
            .expect("snapshots stay admitted")
            .first()
            .expect("slot 0 snapshot")
            .raw_eq(Value::int(5))
    );
    drop(borrow);

    frame.set(0, Value::int(6)).expect("mutation readmitted");
    assert!(frame.get(0).expect("slot reads").raw_eq(Value::int(6)));
}

#[test]
fn persistent_dynamic_environments_share_heads_and_rebuild_writebacks() {
    let mut with_scopes = EvalWithEnv::default();
    with_scopes.push(EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(1),
        Value::int(10),
    ));
    let captured_with = EvalWithEnv::capture_persistent(&with_scopes);
    assert!(Arc::ptr_eq(
        with_scopes.scopes.head.as_ref().expect("active with head"),
        captured_with
            .scopes
            .head
            .as_ref()
            .expect("captured with head")
    ));
    assert_eq!(with_scopes.len(), 1);
    assert!(!with_scopes.is_empty());
    assert!(
        with_scopes
            .scopes
            .head
            .as_ref()
            .is_some_and(|head| head.values.get().is_none())
    );
    assert!(with_scopes.replace_value(0, Value::int(11)));
    assert!(with_scopes[0].value().raw_eq(Value::int(11)));
    assert!(captured_with[0].value().raw_eq(Value::int(10)));

    let mut globals = EvalScopedGlobalEnv::default();
    globals.push(Value::int(20));
    let captured_globals = EvalScopedGlobalEnv::capture_persistent(&globals);
    assert!(Arc::ptr_eq(
        globals.scopes.head.as_ref().expect("active global head"),
        captured_globals
            .scopes
            .head
            .as_ref()
            .expect("captured global head")
    ));
    assert_eq!(globals.len(), 1);
    assert!(!globals.is_empty());
    assert!(
        globals
            .scopes
            .head
            .as_ref()
            .is_some_and(|head| head.values.get().is_none())
    );
    assert!(globals.replace_value(0, Value::int(21)));
    assert!(globals[0].raw_eq(Value::int(21)));
    assert!(captured_globals[0].raw_eq(Value::int(20)));
}

#[test]
fn eval_frame_and_env_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EvalFrame>();
    assert_send_sync::<EvalEnv>();
    assert_send_sync::<EvalWithEnv>();
    assert_send_sync::<EvalScopedGlobalEnv>();
    assert_send_sync::<AtomicValueCell>();
}
