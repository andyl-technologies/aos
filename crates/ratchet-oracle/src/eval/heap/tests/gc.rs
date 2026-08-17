//! Unit tests for Tier-B live reclamation: capture shedding and the
//! quiescent-point non-moving sweep.

use super::*;
use crate::eval::heap::EvalGcMode;

#[path = "payload_identity.rs"]
mod payload_identity;

/// Allocates a suspended thunk that captures one env frame.
fn alloc_capturing_thunk(heap: &mut EvalHeap) -> (Value, Arc<EvalFrame>) {
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, Value::int(11)).expect("slot stores");
    let env = EvalEnv::capture(&[Arc::clone(&frame)]).expect("env captures");
    let thunk = heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(1), env))
        .expect("thunk allocates");
    (thunk, frame)
}

/// Forces `thunk` to `result` through the serial claim protocol.
fn force_thunk_to(heap: &mut EvalHeap, thunk: Value, result: Value) {
    // Publish through the heap record's own serial cell. With inline thunk-cell
    // storage a `clone_thunk` deep-copies the cell, so forcing a clone would
    // leave the heap record suspended; promoting the flat cell to a shared
    // `Arc` and forcing that handle publishes back into the record.
    let cell = heap.test_share_thunk_cell(thunk).expect("thunk resolves");
    let crate::eval::ForceClaim::Claimed(guard) = cell.begin_force().expect("claim succeeds")
    else {
        panic!("thunk should be claimable");
    };
    guard.finish(result).expect("result publishes");
}

#[test]
fn gc_mode_default_is_off() {
    assert_eq!(EvalGcMode::default(), EvalGcMode::Off);
    assert!(!EvalGcMode::Off.is_enabled());
    assert!(EvalGcMode::Sweep.is_enabled());
}

#[test]
fn shed_forced_thunk_drops_captured_env_and_preserves_result() {
    let mut heap = EvalHeap::new();
    let (thunk, frame) = alloc_capturing_thunk(&mut heap);
    force_thunk_to(&mut heap, thunk, Value::int(42));
    // The heap record still holds the capturing kind, keeping the frame alive.
    assert!(Arc::strong_count(&frame) >= 2);

    let shed = heap
        .shed_forced_thunk_captures(thunk)
        .expect("shed succeeds");
    assert!(shed);

    // The captured frame was released; only the test's handle remains.
    assert_eq!(Arc::strong_count(&frame), 1);
    // Identity and the forced result are preserved through the same address.
    let resolved = heap.get_thunk(thunk).expect("thunk still resolves");
    assert!(matches!(resolved.kind(), EvalThunkKind::Released));
    assert_eq!(
        resolved.cell().state().expect("state reads"),
        ThunkState::Forced
    );
    let cached = resolved
        .cell()
        .cached_value()
        .expect("cached value reads")
        .expect("cached value present");
    assert!(cached.raw_eq(Value::int(42)));
    assert_eq!(heap.allocation_counters().thunks_shed(), 1);

    // Shedding is idempotent: a released thunk reports false.
    let again = heap
        .shed_forced_thunk_captures(thunk)
        .expect("second shed succeeds");
    assert!(!again);
    assert_eq!(heap.allocation_counters().thunks_shed(), 1);
}

#[test]
fn shed_flat_thunk_retains_tail_inherited_by_conservative_descendant() {
    let mut heap = EvalHeap::new();
    let site = EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(1));
    let mut capture = EvalFlatCaptureBuffer::new(site, 1);
    capture.push(Value::int(7)).expect("capture value fits");
    let owner = heap
        .alloc_thunk_with_flat_capture(EvalThunk::new(IrId::new(2)), Some(capture.finish()))
        .expect("flat owner allocates")
        .0;
    let inherited = heap
        .get_thunk(owner)
        .expect("owner resolves")
        .env()
        .expect("owner is a node thunk")
        .flat_base()
        .cloned();
    let descendant_env =
        EvalEnv::capture_linked_with_flat_base(&[], inherited).expect("linked capture succeeds");
    let _descendant = heap
        .alloc_thunk(EvalThunk::with_env(
            EvalModuleId::ROOT,
            IrId::new(3),
            descendant_env,
        ))
        .expect("conservative descendant allocates");

    force_thunk_to(&mut heap, owner, Value::int(9));
    assert!(heap.shed_forced_thunk_captures(owner).expect("owner sheds"));
    let values = heap
        .flat_closure_capture_values(owner)
        .expect("owner lookup succeeds")
        .expect("inherited inline tail remains attached");
    assert!(values[0].raw_eq(Value::int(7)));
    assert!(matches!(
        heap.get_thunk(owner).expect("shed owner resolves").kind(),
        EvalThunkKind::Released
    ));
}

#[test]
fn shed_rejects_unforced_thunk() {
    let mut heap = EvalHeap::new();
    let (thunk, _frame) = alloc_capturing_thunk(&mut heap);
    let error = heap
        .shed_forced_thunk_captures(thunk)
        .expect_err("suspended thunk cannot shed");
    assert!(matches!(error, EvalHeapError::ShedRejected { .. }));
}

#[test]
fn shed_skips_single_entry_thunks() {
    let mut heap = EvalHeap::new();
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)).into_single_entry())
        .expect("thunk allocates");
    let shed = heap
        .shed_forced_thunk_captures(thunk)
        .expect("shed consults storage mode before force state");
    assert!(!shed);
}

#[test]
fn sweep_retires_unreachable_worker_records_and_fails_stale_handles_loudly() {
    let mut heap = EvalHeap::new();
    let (reachable, _frame_a) = alloc_capturing_thunk(&mut heap);
    let (unreachable, frame_b) = alloc_capturing_thunk(&mut heap);
    // Promote the inline serial cell to a shared `Arc` and hold a clone: the
    // record and this handle now share one cell (strong count 2). Under the
    // inline-cell storage the record owns the cell directly, so exercising the
    // sweep's sidecar-drop requires this explicit promotion.
    let unreachable_state = heap
        .test_share_thunk_cell(unreachable)
        .expect("unreachable thunk resolves before sweep");
    assert_eq!(Arc::strong_count(&unreachable_state), 2);
    let records_before = heap.len();

    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, reachable)
        .expect("root records");
    let report = heap
        .sweep_unreachable_worker_records(&roots)
        .expect("sweep succeeds");

    assert_eq!(report.swept_thunks, 1);
    assert_eq!(report.swept(), 1);
    assert_eq!(report.live_worker_records, 1);
    assert_eq!(report.retired_total, 1);
    // FV-3: flat closures retire in place with no slot recycling — the
    // record table's free list stays empty (its population is the Tier-B B2
    // proving ground's records only).
    assert_eq!(report.free_slots, 0);
    // The retired payload dropped its captured frame.
    assert_eq!(Arc::strong_count(&frame_b), 1);
    // Sweep dropped the arena-owned payload's sidecar owner; an independent
    // in-flight state handle remains valid until its user releases it.
    assert_eq!(Arc::strong_count(&unreachable_state), 1);
    // The survivor still resolves; the retired handle fails loudly.
    heap.get_thunk(reachable).expect("survivor resolves");
    let error = heap
        .get_thunk(unreachable)
        .expect_err("stale handle fails loudly");
    assert!(matches!(error, EvalHeapError::UnknownPointer { .. }));

    // FV-3: a retired flat closure's entry is a tombstone, not a recycled
    // slot — the next allocation appends (the typed-object count grows by
    // one) and resolves at its own fresh address, while the retired address
    // is never reissued.
    let (fresh, _frame_c) = alloc_capturing_thunk(&mut heap);
    assert_eq!(heap.len(), records_before + 1);
    heap.get_thunk(fresh).expect("fresh flat closure resolves");
    // The stale handle still fails after further allocation (no address
    // reuse).
    let error = heap
        .get_thunk(unreachable)
        .expect_err("stale handle keeps failing after retirement");
    assert!(matches!(error, EvalHeapError::UnknownPointer { .. }));
}

#[test]
fn precise_scan_sweep_keeps_every_scanned_worker_and_retires_only_absent_workers() {
    let mut heap = EvalHeap::new();
    let (live, _live_frame) = alloc_capturing_thunk(&mut heap);
    let (dead, dead_frame) = alloc_capturing_thunk(&mut heap);
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, live)
        .expect("live root records");
    let scan = heap.scan_precise_roots(&roots).expect("root graph scans");

    let report = heap
        .sweep_unreachable_worker_records_from_precise_scan(&scan)
        .expect("scan-driven sweep succeeds");

    assert_eq!(report.marked, 1);
    assert_eq!(report.live_worker_records, 1);
    assert_eq!(report.swept_thunks, 1);
    heap.get_thunk(live).expect("scanned worker remains live");
    assert!(heap.get_thunk(dead).is_err());
    assert_eq!(Arc::strong_count(&dead_frame), 1);
}

#[test]
fn precise_scan_sweep_rejects_blackhole_before_retiring_any_worker() {
    let mut heap = EvalHeap::new();
    let (ordinary_dead, _ordinary_frame) = alloc_capturing_thunk(&mut heap);
    let (blackholed, _blackhole_frame) = alloc_capturing_thunk(&mut heap);
    let cell = heap
        .test_share_thunk_cell(blackholed)
        .expect("blackhole thunk resolves");
    let crate::eval::ForceClaim::Claimed(guard) = cell.begin_force().expect("claim succeeds")
    else {
        panic!("thunk should be claimable");
    };
    let scan = heap
        .scan_precise_roots(&EvalRootSet::new())
        .expect("empty graph scans");

    let error = heap
        .sweep_unreachable_worker_records_from_precise_scan(&scan)
        .expect_err("unreachable blackhole rejects scan-driven sweep");

    assert!(matches!(error, EvalHeapError::ShedRejected { .. }));
    heap.get_thunk(ordinary_dead)
        .expect("ordinary dead worker was not partially retired");
    heap.get_thunk(blackholed)
        .expect("blackholed worker remains live");
    drop(guard);
}

#[test]
fn sweep_keeps_worker_values_reachable_from_permanent_attrs() {
    let mut heap = EvalHeap::new();
    let (thunk, frame) = alloc_capturing_thunk(&mut heap);
    // Intern an attrset holding the thunk: the attrs record is permanent and
    // immortal, so its worker edge must keep the thunk alive with NO explicit
    // roots at all.
    let attrs = attrs_with_value(thunk);
    heap.alloc_attrs(0, attrs).expect("attrs allocate");

    let roots = EvalRootSet::new();
    let report = heap
        .sweep_unreachable_worker_records(&roots)
        .expect("sweep succeeds");
    assert_eq!(report.swept(), 0);
    assert_eq!(report.live_worker_records, 1);
    assert!(report.permanent_edge_seeds >= 1);
    heap.get_thunk(thunk).expect("attrs-held thunk survives");
    assert!(Arc::strong_count(&frame) >= 2);
}

#[test]
fn sweep_traverses_suspended_thunk_captures_transitively() {
    let mut heap = EvalHeap::new();
    // inner is reachable only through outer's captured env slot.
    let (inner, _inner_frame) = alloc_capturing_thunk(&mut heap);
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, inner).expect("slot stores");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let outer = heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(2), env))
        .expect("outer thunk allocates");

    let mut roots = EvalRootSet::new();
    roots.try_push_value_stack(0, outer).expect("root records");
    let report = heap
        .sweep_unreachable_worker_records(&roots)
        .expect("sweep succeeds");
    assert_eq!(report.swept(), 0);
    heap.get_thunk(inner).expect("captured thunk survives");
}

#[test]
fn sweep_drops_forced_thunk_captures_from_reachability() {
    let mut heap = EvalHeap::new();
    // inner is captured by outer, but outer is FORCED to an inline result:
    // a forced thunk's edge set is its cached result only, so inner is
    // unreachable and must be retired.
    let (inner, _inner_frame) = alloc_capturing_thunk(&mut heap);
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, inner).expect("slot stores");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let outer = heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(2), env))
        .expect("outer thunk allocates");
    force_thunk_to(&mut heap, outer, Value::int(7));

    let mut roots = EvalRootSet::new();
    roots.try_push_value_stack(0, outer).expect("root records");
    let report = heap
        .sweep_unreachable_worker_records(&roots)
        .expect("sweep succeeds");
    assert_eq!(report.swept_thunks, 1);
    heap.get_thunk(outer).expect("forced outer survives");
    heap.get_thunk(inner).expect_err("dead capture retired");
}

#[test]
fn sweep_rejects_unreachable_blackholed_thunk() {
    let mut heap = EvalHeap::new();
    let (thunk, _frame) = alloc_capturing_thunk(&mut heap);
    // Blackhole the heap record's own inline serial cell
    // storage makes `clone_thunk` deep-copy the cell, so blackholing a clone
    // would leave the record suspended and the sweep would not see the
    // in-flight force it must reject.
    let cell = heap.test_share_thunk_cell(thunk).expect("thunk resolves");
    let crate::eval::ForceClaim::Claimed(guard) = cell.begin_force().expect("claim succeeds")
    else {
        panic!("thunk should be claimable");
    };

    let roots = EvalRootSet::new();
    let error = heap
        .sweep_unreachable_worker_records(&roots)
        .expect_err("in-flight force rejects the sweep");
    assert!(matches!(error, EvalHeapError::ShedRejected { .. }));
    // No retirement happened: the thunk still resolves.
    heap.get_thunk(thunk).expect("thunk untouched");
    drop(guard);
}

#[test]
fn sweep_rejects_stale_roots_loudly() {
    let mut heap = EvalHeap::new();
    let (thunk, _frame) = alloc_capturing_thunk(&mut heap);
    let mut roots = EvalRootSet::new();
    roots.try_push_value_stack(0, thunk).expect("root records");
    // Retire the thunk out from under the root set to model an incomplete
    // root discipline; the next sweep must fail loudly, not silently mark.
    let report = heap
        .sweep_unreachable_worker_records(&EvalRootSet::new())
        .expect("first sweep retires the thunk");
    assert_eq!(report.swept_thunks, 1);

    let error = heap
        .sweep_unreachable_worker_records(&roots)
        .expect_err("stale root fails the sweep");
    assert!(matches!(error, EvalHeapError::UnknownPointer { .. }));
}

#[test]
fn worker_region_pop_fails_closed_after_sweep_retirement() {
    let mut heap = EvalHeap::new();
    let (_thunk, _frame) = alloc_capturing_thunk(&mut heap);
    let report = heap
        .sweep_unreachable_worker_records(&EvalRootSet::new())
        .expect("sweep retires the unreachable thunk");
    assert_eq!(report.swept(), 1);

    let mark = heap.worker_region_mark().expect("region mark records");
    let error = heap
        .pop_worker_region_if_disconnected(mark)
        .expect_err("region pop is fenced off after retirement");
    assert!(matches!(error, EvalHeapError::RegionPopAfterSweep { .. }));
}

#[test]
fn shed_then_sweep_reports_cycle_counters() {
    let mut heap = EvalHeap::new();
    let (kept, _frame_a) = alloc_capturing_thunk(&mut heap);
    let (dead, _frame_b) = alloc_capturing_thunk(&mut heap);
    force_thunk_to(&mut heap, kept, Value::int(1));
    force_thunk_to(&mut heap, dead, Value::int(2));
    assert!(heap.shed_forced_thunk_captures(kept).expect("shed kept"));
    assert!(heap.shed_forced_thunk_captures(dead).expect("shed dead"));

    let mut roots = EvalRootSet::new();
    roots.try_push_value_stack(0, kept).expect("root records");
    let report = heap
        .sweep_unreachable_worker_records(&roots)
        .expect("sweep succeeds");
    assert_eq!(report.swept_thunks, 1);
    let counters = heap.allocation_counters();
    assert_eq!(counters.thunks_shed(), 2);
    assert_eq!(counters.gc_sweeps(), 1);
    assert_eq!(counters.gc_records_swept(), 1);
}

/// A retained flat closure below the marker whose forced result references
/// the reclaimed suffix rejects the pop, exactly as a retained record did.
#[test]
fn flat_closure_region_pop_rejects_retained_closure_edge_into_suffix() {
    let mut heap = EvalHeap::new();
    let (retained, _frame) = alloc_capturing_thunk(&mut heap);
    let mark = heap.worker_region_mark().expect("region mark records");
    let above = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(20),
            IrId::new(21),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("suffix lambda allocates");
    // Force the retained thunk to the suffix lambda: its cached-result edge
    // now points into the reclaimed region.
    force_thunk_to(&mut heap, retained, above);

    let error = heap
        .pop_worker_region_if_disconnected(mark)
        .expect_err("retained cached-result edge rejects the pop");
    assert!(matches!(
        error,
        EvalHeapError::WorkerRegionPopRetainedEdge { .. }
    ));
    // Nothing was reclaimed: both objects still resolve.
    heap.get_thunk(retained).expect("retained thunk resolves");
    heap.get_lambda(above).expect("suffix lambda resolves");
}

/// Cross-kind resolution over flat closures keeps record error fidelity:
/// a live closure of another kind is a type mismatch, and any retired
/// closure address is an unknown pointer under every requested kind.
// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn flat_closure_resolution_keeps_mismatch_and_retired_fidelity() {
    let mut heap = EvalHeap::new();
    let (thunk, _frame) = alloc_capturing_thunk(&mut heap);
    let thunk_ptr_bits = thunk.payload_bits();

    let error = heap
        .get_lambda(
            Value::heap(
                ValueTag::Lambda,
                std::ptr::NonNull::new(thunk_ptr_bits as *mut crate::value::HeapObject)
                    .expect("thunk address is non-null"),
            )
            .expect("lambda-tagged handle rebuilds"),
        )
        .expect_err("live thunk under a lambda getter is a type mismatch");
    assert!(matches!(
        error,
        EvalHeapError::RecordTypeMismatch {
            expected: ValueTag::Lambda,
            actual: ValueTag::Thunk,
            ..
        }
    ));

    // Retire the thunk through a sweep; every getter then reports unknown.
    force_thunk_to(&mut heap, thunk, Value::int(1));
    let roots = EvalRootSet::new();
    let report = heap
        .sweep_unreachable_worker_records(&roots)
        .expect("sweep succeeds");
    assert_eq!(report.swept_thunks, 1);
    assert!(matches!(
        heap.get_thunk(thunk).expect_err("retired thunk is unknown"),
        EvalHeapError::UnknownPointer { .. }
    ));
    let error = heap
        .get_lambda(
            Value::heap(
                ValueTag::Lambda,
                std::ptr::NonNull::new(thunk_ptr_bits as *mut crate::value::HeapObject)
                    .expect("thunk address is non-null"),
            )
            .expect("lambda-tagged handle rebuilds"),
        )
        .expect_err("retired closure is unknown under every kind");
    assert!(matches!(error, EvalHeapError::UnknownPointer { .. }));
}
