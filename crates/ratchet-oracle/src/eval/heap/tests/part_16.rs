//! Evaluator-heap unit tests, part 16 of 16 (RFC-0007 §2 split, #9).
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
fn collector_poll_minor_gc_plan_uses_remembered_old_edge() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    // Lists are flat and permanent since FV-1; a permanent source is the
    // remaining non-young remembered-edge source shape a list can take.
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent flat list allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");

    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("old remembered edge is accepted");

    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert!(planned.reference_slots().iter().any(|slot| {
        slot.source()
            == &AllocationCollectorPollReferenceSource::RememberedEdge {
                edge: RememberedEdge::new(gc_address(root), gc_address(child)),
                field_index: 0,
                source: HeapEdgeSource::ListElement { index: 0 },
            }
    }));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_plan_rejects_unremembered_permanent_edge_outside_root_graph() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("root thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots.try_push_value_stack(0, root).expect("root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("missing remembered edge is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollRememberedEdge {
            source_address: gc_address(permanent_parent),
            target_address: gc_address(child),
        }
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_plan_rejects_stale_heap_graph_snapshot() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let forced = heap
        .alloc_string(NixString::from_bytes(b"forced".to_vec()))
        .expect("forced value allocates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_force_continuation(0, thunk)
        .expect("thunk root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    let claim = thunk_record.cell().begin_force().expect("claim succeeds");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new thunk should be claimable");
    };
    guard.finish(forced).expect("thunk publishes forced value");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("stale snapshot is rejected");

    assert_eq!(
        error,
        EvalHeapError::CollectorPollScanStaleObject {
            address: gc_address(thunk),
        }
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn collector_poll_minor_gc_plan_rejects_heap_growth_after_scan() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_force_continuation(0, thunk)
        .expect("thunk root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let snapshot_records = scan.heap_records();
    heap.alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("later thunk allocates");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("heap growth after scan is rejected");

    assert_eq!(
        error,
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "heap record count changed",
            expected_records: snapshot_records,
            actual_records: heap.len(),
        }
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_tracks_thunk_state_instead_of_stale_captures() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let captured = heap
        .alloc_string(NixString::from_bytes(b"captured".to_vec()))
        .expect("captured string allocates");
    let forced = heap
        .alloc_string(NixString::from_bytes(b"forced".to_vec()))
        .expect("forced string allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, captured).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let thunk = heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(9), env))
        .expect("thunk allocates");
    let mut roots = EvalRootSet::new();
    assert!(
        roots
            .try_push_force_continuation(0, thunk)
            .expect("thunk root records")
    );

    let suspended_scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let suspended_edges = object_for(&suspended_scan, thunk).edges();
    assert_eq!(suspended_edges.len(), 1);
    assert_eq!(
        suspended_edges[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        }
    );
    assert!(suspended_edges[0].value().raw_eq(captured));

    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    let claim = thunk_record.cell().begin_force().expect("claim succeeds");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new thunk should be claimable");
    };
    guard.finish(forced).expect("thunk publishes forced value");

    let forced_scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let forced_edges = object_for(&forced_scan, thunk).edges();
    assert_eq!(forced_edges.len(), 1);
    assert_eq!(forced_edges[0].source(), &HeapEdgeSource::ThunkCachedResult);
    assert!(forced_edges[0].value().raw_eq(forced));
    assert!(object_for(&forced_scan, forced).edges().is_empty());
    assert!(
        forced_scan
            .objects()
            .iter()
            .all(|object| !object.value().raw_eq(captured))
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_reports_parallel_thunk_payload_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let captured = heap
        .alloc_string(NixString::from_bytes(b"captured".to_vec()))
        .expect("captured string allocates");
    let payload = heap
        .alloc_string(NixString::from_bytes(b"parallel".to_vec()))
        .expect("parallel payload string allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, captured).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let thunk = heap
        .alloc_thunk(
            EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(9), env)
                .with_parallel_payload_cell(tree_walk_error(99), None),
        )
        .expect("thunk allocates");
    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    publish_parallel_payload(&thunk_record, payload);

    let mut roots = EvalRootSet::new();
    assert!(
        roots
            .try_push_force_continuation(0, thunk)
            .expect("thunk root records")
    );
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");

    let edges = object_for(&scan, thunk).edges();
    assert_eq!(edges.len(), 2);
    assert_eq!(
        edges[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        }
    );
    assert!(edges[0].value().raw_eq(captured));
    assert_eq!(
        edges[1].source(),
        &HeapEdgeSource::ThunkParallelPayloadValue
    );
    assert!(edges[1].value().raw_eq(payload));
    assert!(object_for(&scan, payload).edges().is_empty());
    assert_eq!(thunk_record.cell().state(), Ok(ThunkState::Suspended));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_reports_lambda_captured_scopes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let lexical = heap
        .alloc_string(NixString::from_bytes(b"lexical".to_vec()))
        .expect("lexical string allocates");
    let with_scope = heap
        .alloc_string(NixString::from_bytes(b"with".to_vec()))
        .expect("with string allocates");
    let scoped_global = heap
        .alloc_string(NixString::from_bytes(b"global".to_vec()))
        .expect("global string allocates");
    let frame = EvalFrame::new(2).expect("frame allocates");
    frame.set(0, lexical).expect("slot writes");
    frame.set(1, Value::int(9)).expect("inline slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(3),
        with_scope,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[scoped_global]).expect("global env captures");
    let lambda = heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            env,
            with_env,
            scoped_globals,
        ))
        .expect("lambda allocates");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, lambda)
        .expect("lambda root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, lambda).edges();

    assert_eq!(edges.len(), 3);
    assert!(
        edges.iter().any(|edge| {
            edge.source()
                == &HeapEdgeSource::CapturedEnv {
                    owner: CapturedRootOwner::Lambda,
                    frame: 0,
                    slot: 0,
                }
                && edge.value().raw_eq(lexical)
        }),
        "lexical heap slot is reported"
    );
    assert!(
        edges.iter().any(|edge| {
            edge.source()
                == &HeapEdgeSource::CapturedWithScope {
                    owner: CapturedRootOwner::Lambda,
                    index: 0,
                }
                && edge.value().raw_eq(with_scope)
        }),
        "with-scope heap value is reported"
    );
    assert!(
        edges.iter().any(|edge| {
            edge.source()
                == &HeapEdgeSource::CapturedScopedGlobal {
                    owner: CapturedRootOwner::Lambda,
                    index: 0,
                }
                && edge.value().raw_eq(scoped_global)
        }),
        "scoped-global heap value is reported"
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_reports_primop_heap_arguments() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let argument_value = heap
        .alloc_string(NixString::from_bytes(b"arg".to_vec()))
        .expect("argument string allocates");
    let primop = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![
                EvalPrimOpArg::new(IrId::new(1), Span::new(0, 1), Value::int(1)),
                EvalPrimOpArg::new(IrId::new(2), Span::new(1, 2), argument_value),
            ],
        ))
        .expect("primop allocates");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_primop_argument(0, primop)
        .expect("primop root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, primop).edges();

    assert_eq!(edges.len(), 1);
    assert_eq!(
        edges[0].source(),
        &HeapEdgeSource::PrimopArgument { index: 1 }
    );
    assert!(edges[0].value().raw_eq(argument_value));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_reports_suspended_thunk_capture_variants() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let function_value = heap
        .alloc_string(NixString::from_bytes(b"function".to_vec()))
        .expect("function string allocates");
    let argument_value = heap
        .alloc_string(NixString::from_bytes(b"argument".to_vec()))
        .expect("argument string allocates");
    let first_argument_value = heap
        .alloc_string(NixString::from_bytes(b"first".to_vec()))
        .expect("first string allocates");
    let second_argument_value = heap
        .alloc_string(NixString::from_bytes(b"second".to_vec()))
        .expect("second string allocates");
    let receiver = heap
        .alloc_string(NixString::from_bytes(b"receiver".to_vec()))
        .expect("receiver string allocates");
    let apply = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(1),
            Span::new(0, 1),
            function_value,
            EvalModuleId::ROOT,
            IrId::new(2),
            argument_value,
        ))
        .expect("apply thunk allocates");
    let apply2 = heap
        .alloc_thunk(EvalThunk::apply2(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(1, 2),
            function_value,
            EvalModuleId::ROOT,
            IrId::new(4),
            Span::new(2, 3),
            first_argument_value,
            EvalModuleId::ROOT,
            IrId::new(5),
            Span::new(3, 4),
            second_argument_value,
        ))
        .expect("apply2 thunk allocates");
    let select = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(6),
            receiver,
            IrAttrPathId::new(0),
        ))
        .expect("select thunk allocates");
    let builtin_attr = heap
        .alloc_thunk(EvalThunk::builtin_attr(symbol, builtin))
        .expect("builtin attr thunk allocates");
    let mut roots = EvalRootSet::new();
    for (index, value) in [apply, apply2, select, builtin_attr]
        .into_iter()
        .enumerate()
    {
        roots
            .try_push_value_stack(index, value)
            .expect("thunk root records");
    }

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let apply_edges = object_for(&scan, apply).edges();
    assert_eq!(apply_edges.len(), 2);
    assert!(
        apply_edges
            .iter()
            .any(|edge| edge.source() == &HeapEdgeSource::ThunkApplyFunction
                && edge.value().raw_eq(function_value))
    );
    assert!(
        apply_edges
            .iter()
            .any(|edge| edge.source() == &HeapEdgeSource::ThunkApplyArgument
                && edge.value().raw_eq(argument_value))
    );

    let apply2_edges = object_for(&scan, apply2).edges();
    assert_eq!(apply2_edges.len(), 3);
    assert!(
        apply2_edges
            .iter()
            .any(|edge| edge.source() == &HeapEdgeSource::ThunkApply2Function
                && edge.value().raw_eq(function_value))
    );
    assert!(apply2_edges.iter().any(|edge| edge.source()
        == &HeapEdgeSource::ThunkApply2FirstArgument
        && edge.value().raw_eq(first_argument_value)));
    assert!(apply2_edges.iter().any(|edge| edge.source()
        == &HeapEdgeSource::ThunkApply2SecondArgument
        && edge.value().raw_eq(second_argument_value)));

    let select_edges = object_for(&scan, select).edges();
    assert_eq!(select_edges.len(), 1);
    assert_eq!(
        select_edges[0].source(),
        &HeapEdgeSource::ThunkSelectReceiver
    );
    assert!(select_edges[0].value().raw_eq(receiver));
    assert!(object_for(&scan, builtin_attr).edges().is_empty());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_reports_blackholed_thunk_captures() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let captured = heap
        .alloc_string(NixString::from_bytes(b"captured".to_vec()))
        .expect("captured string allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, captured).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let thunk = heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(9), env))
        .expect("thunk allocates");
    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    let claim = thunk_record.cell().begin_force().expect("claim succeeds");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new thunk should be claimable");
    };
    let mut roots = EvalRootSet::new();
    roots
        .try_push_force_continuation(0, thunk)
        .expect("thunk root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, thunk).edges();

    assert_eq!(edges.len(), 1);
    assert_eq!(
        edges[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        }
    );
    assert!(edges[0].value().raw_eq(captured));
    guard.abort().expect("claim aborts");
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_ignores_external_heap_values_owned_elsewhere() {
    let external =
        Value::external(NonNull::<HeapObject>::dangling()).expect("external pointer builds");
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap
        .alloc_list(NixList::new(vec![external]))
        .expect("list allocates");
    let mut roots = EvalRootSet::new();

    assert!(
        !roots
            .try_push_value_stack(0, external)
            .expect("external root ignored")
    );
    roots
        .try_push_value_stack(1, list)
        .expect("list root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");

    assert_eq!(scan.roots().len(), 1);
    assert_eq!(scan.objects().len(), 1);
    assert!(object_for(&scan, list).edges().is_empty());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn interned_root_set_enumerates_hash_consed_permanent_roots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"interned".to_vec()))
        .expect("string allocates");
    let second_string = heap
        .alloc_string(NixString::from_bytes(b"interned-second".to_vec()))
        .expect("second string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(b"/tmp/interned".to_vec()))
        .expect("path allocates");
    let list = heap
        .alloc_list(NixList::new(vec![string]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(0, attrs_with_value(list))
        .expect("attrs allocate");

    let roots = heap.interned_root_set().expect("interned roots collect");
    let repeated_roots = heap.interned_root_set().expect("interned roots repeat");
    let sources: Vec<_> = roots.roots().iter().map(EvalRoot::source).collect();

    assert_eq!(roots.roots(), repeated_roots.roots());
    assert_eq!(roots.len(), 5);
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 1,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::Path,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::List,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::Attrs,
        index: 0,
    }));

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(string))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(second_string))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(path))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(list))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(attrs))
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn precise_root_scan_validates_duplicate_address_tags_before_deduping() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("list allocates");
    let ptr = list.as_list_ptr().expect("list pointer");
    let mislabeled = Value::string(ptr).expect("same pointer can carry another heap tag");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, list)
        .expect("list root records");
    roots
        .try_push_value_stack(1, mislabeled)
        .expect("mislabeled root records");

    let error = heap
        .scan_precise_roots(&roots)
        .expect_err("mislabeled duplicate is rejected");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, ptr)
    );
}
