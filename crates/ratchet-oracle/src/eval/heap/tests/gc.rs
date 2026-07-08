//! Unit tests for Tier-B live reclamation: capture shedding and the
//! quiescent-point non-moving sweep.

use super::*;
use crate::eval::heap::EvalGcMode;

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
fn force_thunk_to(heap: &EvalHeap, thunk: Value, result: Value) {
    let shared = heap.clone_thunk(thunk).expect("thunk resolves");
    let crate::eval::ForceClaim::Claimed(guard) =
        shared.cell().begin_force().expect("claim succeeds")
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
    force_thunk_to(&heap, thunk, Value::int(42));
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
    assert_eq!(report.free_slots, 1);
    // The retired payload dropped its captured frame.
    assert_eq!(Arc::strong_count(&frame_b), 1);
    // The survivor still resolves; the retired handle fails loudly.
    heap.get_thunk(reachable).expect("survivor resolves");
    let error = heap
        .get_thunk(unreachable)
        .expect_err("stale handle fails loudly");
    assert!(matches!(error, EvalHeapError::UnknownPointer { .. }));

    // The retired slot is recycled by the next allocation: the record table
    // does not grow, and the fresh record resolves at its own new address.
    let (fresh, _frame_c) = alloc_capturing_thunk(&mut heap);
    assert_eq!(heap.len(), records_before);
    heap.get_thunk(fresh).expect("recycled-slot record resolves");
    // The stale handle still fails after recycling (no address reuse).
    let error = heap
        .get_thunk(unreachable)
        .expect_err("stale handle keeps failing after slot recycling");
    assert!(matches!(error, EvalHeapError::UnknownPointer { .. }));
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
    force_thunk_to(&heap, outer, Value::int(7));

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
    let shared = heap.clone_thunk(thunk).expect("thunk resolves");
    let crate::eval::ForceClaim::Claimed(guard) =
        shared.cell().begin_force().expect("claim succeeds")
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
    force_thunk_to(&heap, kept, Value::int(1));
    force_thunk_to(&heap, dead, Value::int(2));
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
