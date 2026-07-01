//! Tree-walk safepoint root-set tests.

use super::*;
use crate::eval::heap::{AllocationCollectorPollScan, EvalRoot, EvalRootSource, InternedRootTable};
use crate::heap::{GcHeapAddress, MinorGcPromotionPolicy, RememberedSet};
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};
use std::path::PathBuf;

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

fn scan_has_value_stack_root(scan: &AllocationCollectorPollScan, value: Value) -> bool {
    scan.scan().roots().iter().any(|scan_root| {
        scan_root.source() == &EvalRootSource::ValueStack { slot: 0 }
            && scan_root.value().raw_eq(value)
    })
}

fn scan_has_object(scan: &AllocationCollectorPollScan, value: Value) -> bool {
    scan.scan()
        .objects()
        .iter()
        .any(|object| object.value().raw_eq(value))
}

#[test]
fn safepoint_roots_include_active_tree_walk_state_and_interned_roots() {
    let ir = lower("null");
    let mut evaluator = TreeWalk::new(&ir);
    let live = evaluator
        .heap
        .alloc_string(NixString::from_bytes(b"live-root".to_vec()))
        .expect("string allocates");

    let frame = EvalFrame::new(3).expect("frame allocates");
    frame.set(1, live).expect("frame slot sets");
    evaluator.env.push(frame);
    evaluator
        .with_scopes
        .push(EvalWithScope::new(EvalModuleId::ROOT, ir.root, live));
    evaluator.scoped_globals.push(live);
    evaluator
        .push_active_force_root(ir.root, Span::new(0, 0), live)
        .expect("force root pushes");
    evaluator
        .push_active_primop_arg_roots(
            ir.root,
            Span::new(0, 0),
            &[EvalPrimOpArg::new(ir.root, Span::new(0, 0), live)],
        )
        .expect("primop roots push");
    let suspended_frame = EvalFrame::new(2).expect("suspended frame allocates");
    suspended_frame
        .set(0, live)
        .expect("suspended frame slot sets");
    evaluator
        .reserve_suspended_env_root_frame(ir.root, Span::new(0, 0))
        .expect("suspended env root reserves");
    evaluator.push_suspended_env_roots(
        vec![suspended_frame],
        vec![EvalWithScope::new(EvalModuleId::ROOT, ir.root, live)],
        vec![live],
    );
    evaluator.import_cache.insert(
        PathBuf::from("/tmp/safepoint-root-import.nix"),
        ImportCacheEntry::Ready {
            value: live,
            trace: Some(Vec::new()),
            force_cache_trace_complete: true,
        },
    );

    let roots = evaluator
        .safepoint_root_set()
        .expect("safepoint roots build");
    let sources: Vec<_> = roots.roots().iter().map(EvalRoot::source).collect();

    assert!(sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 1 }));
    assert!(sources.contains(&&EvalRootSource::WithScope { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ScopedGlobal { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::ForceContinuation { depth: 0 }));
    assert!(sources.contains(&&EvalRootSource::TreeWalkPrimopArgument {
        call_depth: 0,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedTreeWalkFrame {
        depth: 0,
        frame: 0,
        slot: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedWithScope {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::SuspendedScopedGlobal {
        depth: 0,
        scope_depth: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::ImportCache { index: 0 }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 0,
    }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 0 }));
    assert!(!sources.contains(&&EvalRootSource::TreeWalkFrame { frame: 0, slot: 2 }));

    let scan = evaluator
        .safepoint_heap_scan()
        .expect("safepoint heap scans");
    assert!(scan.roots().iter().any(|root| root.value().raw_eq(live)));
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(live))
    );
}

#[test]
fn active_safepoint_roots_are_removed_after_force_and_primop_errors() {
    let recursive = lower("let x = x; in x");
    let mut recursive_eval = TreeWalk::new(&recursive);
    recursive_eval
        .eval_root()
        .expect_err("recursive force reports blackhole");
    let recursive_roots = recursive_eval
        .safepoint_root_set()
        .expect("roots build after force error");
    assert!(recursive_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));

    let bad_primop = lower("let add = builtins.add; in add 1 \"x\"");
    let mut primop_eval = TreeWalk::new(&bad_primop);
    primop_eval
        .eval_root()
        .expect_err("bad first-class primop reports type error");
    let primop_roots = primop_eval
        .safepoint_root_set()
        .expect("roots build after primop error");
    assert!(primop_roots.roots().iter().all(|root| {
        !matches!(
            root.source(),
            EvalRootSource::TreeWalkPrimopArgument { .. }
                | EvalRootSource::ForceContinuation { .. }
                | EvalRootSource::SuspendedTreeWalkFrame { .. }
                | EvalRootSource::SuspendedWithScope { .. }
                | EvalRootSource::SuspendedScopedGlobal { .. }
        )
    }));
}

#[test]
fn gc_stress_poll_scan_uses_tree_walk_roots_plus_transient_value_stack() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let root = evaluator.eval_root().expect("lambda evaluates");
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("lambda allocation requested a collector poll");

    assert_eq!(
        poll.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );

    let remembered_set = RememberedSet::new();
    let empty_scan = evaluator
        .safepoint_collector_poll_scan(poll, [])
        .expect("collector poll scan accepts empty transient roots");
    assert!(empty_scan.scan().roots().is_empty());
    let empty_minor_gc = evaluator
        .heap()
        .plan_collector_poll_minor_gc(
            &empty_scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("empty collector poll scan plans");
    assert!(empty_minor_gc.plan().survivors().is_empty());

    let scan = evaluator
        .safepoint_collector_poll_scan(poll, [root])
        .expect("collector poll roots scan");
    let stack_root = scan
        .scan()
        .roots()
        .iter()
        .find(|scan_root| scan_root.source() == &EvalRootSource::ValueStack { slot: 0 })
        .expect("transient value-stack root records");
    assert!(stack_root.value().raw_eq(root));
    assert!(
        scan.scan()
            .objects()
            .iter()
            .any(|object| { object.value().raw_eq(root) })
    );

    let minor_gc = evaluator
        .heap()
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("collector poll minor-GC planning accepts the tree-walk scan");
    assert_eq!(minor_gc.plan().survivors().len(), 1);
    assert_eq!(minor_gc.plan().survivors()[0].address(), gc_address(root));
}

#[test]
fn owned_eval_records_gc_stress_boundary_worker_scan() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");

    let scans = outcome.gc_stress_boundary_scans();
    assert_eq!(scans.len(), 1);
    assert!(scans.permanent_shared().is_none());
    let worker_scan = scans.worker().expect("worker boundary scan records");
    assert_eq!(
        worker_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert_eq!(
        worker_scan.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert!(scan_has_value_stack_root(worker_scan, outcome.value()));
    assert!(scan_has_object(worker_scan, outcome.value()));
}

#[test]
fn owned_eval_records_gc_stress_boundary_permanent_scan() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let scans = outcome.gc_stress_boundary_scans();
    assert_eq!(scans.len(), 1);
    assert!(scans.worker().is_none());
    let permanent_scan = scans
        .permanent_shared()
        .expect("permanent boundary scan records");
    assert_eq!(
        permanent_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        permanent_scan.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert!(scan_has_value_stack_root(permanent_scan, outcome.value()));
    assert!(scan_has_object(permanent_scan, outcome.value()));
}

#[test]
fn attr_path_eval_records_gc_stress_boundary_scan() {
    let ir = lower("{ f = x: x; }");
    let outcome = eval_instantiation_attr_path_owned_with_options_and_realizer(
        &ir,
        &[b"f".to_vec()],
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
        None,
    )
    .expect("attr-path selection evaluates under GC stress");

    let worker_scan = outcome
        .gc_stress_boundary_scans()
        .worker()
        .expect("selected lambda boundary scan records");
    assert_eq!(
        worker_scan.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocLambda
    );
    assert!(scan_has_value_stack_root(worker_scan, outcome.value()));
    assert!(scan_has_object(worker_scan, outcome.value()));
}

#[test]
fn gc_stress_poll_scan_rejects_stale_allocator_poll() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let first_root = evaluator.eval_root().expect("first lambda evaluates");
    let first_poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("first lambda allocation requested a collector poll");
    let _second_root = evaluator.eval_root().expect("second lambda evaluates");

    let error = evaluator
        .safepoint_collector_poll_scan(first_poll, [first_root])
        .expect_err("stale collector poll is rejected");

    match error {
        TreeWalkSafepointScanError::StaleCollectorPoll {
            poll,
            current: Some(current),
        } => {
            assert_eq!(poll, first_poll);
            assert_ne!(current, first_poll);
            assert_eq!(
                current.entrypoint(),
                RuntimeAllocationEntryPoint::AosAllocLambda
            );
            assert_eq!(
                current.reason(),
                AllocationGcPollReason::GcStressEverySafepoint
            );
        }
        other => panic!("unexpected stale poll error: {other:?}"),
    }
}
