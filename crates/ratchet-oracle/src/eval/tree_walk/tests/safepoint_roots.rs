//! Tree-walk safepoint root-set tests.

use super::*;
use crate::eval::heap::{
    AllocationCollectorPollScan, EvalRoot, EvalRootSource, HeapAllocationDomain, InternedRootTable,
};
use crate::heap::{
    GcCardTable, GcHeapAddress, GenerationalGcTier, HeapGeneration, MinorGcDestinationBases,
    MinorGcPromotionPolicy, RememberedSet, ResolvedValueGeneration,
};
use crate::list::NixList;
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};
use std::path::PathBuf;

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

fn static_gc_address(address_bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(address_bits).expect("static address is a valid GC address")
}

fn next_dirty_card_source(card_table: &GcCardTable) -> GcHeapAddress {
    let next_index = card_table
        .dirty_cards()
        .iter()
        .map(|card| card.index())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    static_gc_address(next_index.saturating_mul(card_table.card_size_bytes()))
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
fn owned_eval_plans_gc_stress_boundary_worker_minor_gc() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("boundary scan plans as minor GC");

    assert_eq!(plans.len(), 1);
    assert!(plans.permanent_shared().is_none());
    let worker_plan = plans.worker().expect("worker boundary plan records");
    assert_eq!(
        worker_plan.roots(),
        &[ResolvedValueGeneration::young(gc_address(outcome.value()))]
    );
    assert_eq!(worker_plan.plan().survivors().len(), 1);
    assert_eq!(
        worker_plan.plan().survivors()[0].address(),
        gc_address(outcome.value())
    );
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_minor_gc() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("boundary scan plans as minor GC");

    assert_eq!(plans.len(), 1);
    assert!(plans.worker().is_none());
    let permanent_plan = plans
        .permanent_shared()
        .expect("permanent boundary plan records");
    let permanent_root = ResolvedValueGeneration::permanent(gc_address(outcome.value()));
    assert_eq!(permanent_plan.roots().len(), 2);
    assert!(
        permanent_plan
            .roots()
            .iter()
            .all(|root| *root == permanent_root)
    );
    assert!(permanent_plan.plan().is_empty());
}

#[test]
fn owned_eval_plans_gc_stress_boundary_worker_relocation_destinations() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);
    let old_base = static_gc_address(0x2000_0000);

    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, old_base),
        )
        .expect("boundary scan plans relocation destinations");

    assert_eq!(destinations.len(), 1);
    assert!(destinations.permanent_shared().is_none());
    let worker_destinations = destinations
        .worker()
        .expect("worker relocation destinations record");
    assert_eq!(worker_destinations.destinations().len(), 1);
    assert_eq!(
        worker_destinations.destinations()[0].source(),
        gc_address(outcome.value())
    );
    assert_eq!(
        worker_destinations.destinations()[0].destination(),
        nursery_base
    );
    assert_eq!(
        worker_destinations.placement_plan().placements()[0].destination_generation(),
        HeapGeneration::Young
    );
    assert!(worker_destinations.allocation_plan().nursery_bytes() > 0);
    assert_eq!(worker_destinations.allocation_plan().old_bytes(), 0);
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_relocation_destinations() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan plans relocation destinations");

    assert_eq!(destinations.len(), 1);
    assert!(destinations.worker().is_none());
    let permanent_destinations = destinations
        .permanent_shared()
        .expect("permanent relocation report records");
    assert!(permanent_destinations.destinations().is_empty());
    assert_eq!(permanent_destinations.allocation_plan().nursery_bytes(), 0);
    assert_eq!(permanent_destinations.allocation_plan().old_bytes(), 0);
}

#[test]
fn owned_eval_plans_gc_stress_boundary_worker_commit_metadata() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("boundary scan builds paired relocation plan");

    assert_eq!(plans.len(), 1);
    assert!(plans.permanent_shared().is_none());
    let worker_plan = plans.worker().expect("worker paired plan records");
    assert_eq!(worker_plan.minor_gc_plan().plan().survivors().len(), 1);
    assert_eq!(
        worker_plan.relocation_destinations().destinations()[0].destination(),
        nursery_base
    );
    let commit = worker_plan
        .commit_plan()
        .expect("paired boundary plan builds commit metadata");
    assert_eq!(
        commit.reference_slots(),
        worker_plan.minor_gc_plan().reference_slots()
    );
    assert_eq!(commit.commit_plan().object_copies().copies().len(), 1);
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].destination(),
        nursery_base
    );
    assert_eq!(
        commit.commit_plan().forwarding_pointers().pointers().len(),
        1
    );
    assert_eq!(
        commit
            .root_writeback_plan()
            .expect("root writeback metadata builds")
            .len(),
        1
    );
}

#[test]
fn owned_eval_plans_gc_stress_boundary_permanent_commit_metadata() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan builds paired relocation plan");

    assert_eq!(plans.len(), 1);
    assert!(plans.worker().is_none());
    let permanent_plan = plans
        .permanent_shared()
        .expect("permanent paired plan records");
    assert!(permanent_plan.minor_gc_plan().plan().is_empty());
    assert!(
        permanent_plan
            .relocation_destinations()
            .destinations()
            .is_empty()
    );
    let commit = permanent_plan
        .commit_plan()
        .expect("empty permanent boundary plan builds commit metadata");
    assert!(commit.commit_plan().object_copies().is_empty());
    assert!(commit.commit_plan().reference_rewrites().is_empty());
    assert!(
        commit
            .root_writeback_plan()
            .expect("empty root writeback metadata builds")
            .is_empty()
    );
}

#[test]
fn owned_eval_reports_gc_stress_boundary_worker_commit_preflight() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("boundary scan builds commit preflight metadata");

    assert_eq!(preflights.len(), 1);
    assert!(preflights.permanent_shared().is_none());
    let preflight = preflights.worker().expect("worker preflight records");
    assert_eq!(
        preflight
            .relocation_plan()
            .minor_gc_plan()
            .plan()
            .survivors()
            .len(),
        1
    );
    assert_eq!(preflight.object_byte_copy_plan().len(), 1);
    assert_eq!(
        preflight.object_byte_copy_plan().requests()[0].destination(),
        nursery_base
    );
    assert_eq!(preflight.forwarding_slots().len(), 1);
    assert_eq!(
        preflight.forwarding_slots()[0].source(),
        gc_address(outcome.value())
    );
    assert!(preflight.forwarding_slots()[0].is_empty());
    assert_eq!(
        preflight.reference_buffer(),
        &[ResolvedValueGeneration::young(gc_address(outcome.value()))]
    );
    assert_eq!(preflight.reference_writeback_plan().len(), 1);
    assert_eq!(
        preflight.reference_writeback_plan().root_writebacks().len(),
        1
    );
    assert!(
        preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .is_empty()
    );
    let application = preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("boundary preflight applies owned writeback slots");
    assert_eq!(application.report().root_writebacks(), 1);
    assert_eq!(application.report().heap_field_writebacks(), 0);
    assert_eq!(
        application.root_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    let commit_application = preflight
        .apply_commit_to_owned_buffers()
        .expect("boundary preflight applies owned commit buffers");
    let commit_report = commit_application.report();
    assert_eq!(commit_report.object_copies(), 1);
    assert_eq!(commit_report.copied_to_nursery(), 1);
    assert_eq!(commit_report.promoted_to_old(), 0);
    assert_eq!(commit_report.forwarding_pointers(), 1);
    assert_eq!(commit_report.reference_rewrites(), 1);
    assert_eq!(commit_report.remembered_set_source_edges(), 0);
    assert_eq!(commit_report.remembered_set_published_edges(), 0);
    let object_copy = &commit_application.object_byte_copies()[0];
    assert_eq!(
        object_copy.request(),
        preflight.object_byte_copy_plan().requests()[0]
    );
    assert_eq!(
        object_copy.source_bytes().len(),
        object_copy.request().size_bytes()
    );
    assert_eq!(object_copy.destination_bytes(), object_copy.source_bytes());
    let destination_storage = commit_application.destination_storage();
    assert_eq!(
        destination_storage.copy_report().object_copies(),
        commit_report.object_copies()
    );
    assert_eq!(destination_storage.copy_report().copied_to_nursery(), 1);
    assert_eq!(destination_storage.copy_report().promoted_to_old(), 0);
    assert_eq!(
        destination_storage.copy_report().nursery_payload_bytes(),
        object_copy.request().size_bytes()
    );
    assert_eq!(
        destination_storage.nursery_reserved_bytes(),
        preflight
            .relocation_plan()
            .relocation_destinations()
            .placement_plan()
            .nursery_reserved_bytes()
    );
    assert_eq!(destination_storage.old_reserved_bytes(), 0);
    assert_eq!(
        destination_storage.nursery_destination_bytes(),
        object_copy.source_bytes()
    );
    assert!(destination_storage.old_destination_bytes().is_empty());
    assert_eq!(
        commit_application.forwarding_slots()[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        commit_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }]
    );
    assert!(commit_application.remembered_set().is_empty());

    let applications = preflights
        .apply_reference_writebacks_to_owned_slots()
        .expect("boundary preflights apply owned writeback slots");
    assert_eq!(applications.len(), 1);
    assert_eq!(applications.worker(), Some(&application));
    assert!(applications.permanent_shared().is_none());
    let commit_applications = preflights
        .apply_commits_to_owned_buffers()
        .expect("boundary preflights apply owned commit buffers");
    assert_eq!(commit_applications.len(), 1);
    assert_eq!(commit_applications.worker(), Some(&commit_application));
    assert!(commit_applications.permanent_shared().is_none());
}

#[test]
fn owned_eval_runs_gc_stress_boundary_worker_commit_dry_run() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("boundary scan runs owned commit dry-run");

    assert_eq!(dry_run.len(), 1);
    assert!(!dry_run.is_empty());
    assert!(dry_run.preflights().permanent_shared().is_none());
    assert!(dry_run.reference_writebacks().permanent_shared().is_none());
    assert!(dry_run.commit_applications().permanent_shared().is_none());
    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.object_copies(), 1);
    assert_eq!(summary.copied_to_nursery(), 1);
    assert_eq!(summary.promoted_to_old(), 0);
    assert!(summary.object_copy_bytes() > 0);
    assert_eq!(summary.object_copy_bytes(), summary.copy_to_nursery_bytes());
    assert_eq!(summary.promote_to_old_bytes(), 0);
    assert_eq!(summary.forwarding_pointers(), 1);
    assert_eq!(summary.reference_rewrites(), 1);
    assert_eq!(summary.root_writebacks(), 1);
    assert_eq!(summary.heap_field_writebacks(), 0);
    assert_eq!(summary.reference_writebacks(), 1);
    assert_eq!(summary.remembered_set_source_edges(), 0);
    assert_eq!(summary.remembered_set_published_edges(), 0);

    let preflight = dry_run
        .preflights()
        .worker()
        .expect("worker dry-run preflight records");
    let writeback_application = dry_run
        .reference_writebacks()
        .worker()
        .expect("worker dry-run writebacks record");
    let commit_application = dry_run
        .commit_applications()
        .worker()
        .expect("worker dry-run commit records");

    assert_eq!(preflight.object_byte_copy_plan().len(), 1);
    assert_eq!(
        preflight.object_copy_bytes(),
        preflight.object_byte_copy_plan().copy_to_nursery_bytes()
    );
    assert_eq!(preflight.promote_to_old_bytes(), 0);
    assert_eq!(summary.object_copy_bytes(), preflight.object_copy_bytes());
    assert_eq!(
        writeback_application.report().root_writebacks(),
        preflight.reference_writeback_plan().root_writebacks().len()
    );
    assert_eq!(
        writeback_application.report().heap_field_writebacks(),
        preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .len()
    );
    assert_eq!(
        writeback_application.root_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    let commit_report = commit_application.report();
    assert_eq!(
        commit_report.object_copies(),
        preflight.object_byte_copy_plan().len()
    );
    assert_eq!(
        commit_report.forwarding_pointers(),
        preflight.forwarding_slots().len()
    );
    assert_eq!(
        commit_report.reference_rewrites(),
        writeback_application.report().writebacks()
    );
    assert_eq!(commit_report.copied_to_nursery(), 1);
    assert_eq!(commit_report.promoted_to_old(), 0);

    let object_copy = &commit_application.object_byte_copies()[0];
    assert_eq!(
        object_copy.request(),
        preflight.object_byte_copy_plan().requests()[0]
    );
    assert_eq!(object_copy.destination_bytes(), object_copy.source_bytes());
    assert_eq!(
        commit_application.forwarding_slots()[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        commit_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }]
    );

    let live_dirty_source = next_dirty_card_source(outcome.thunk_resolve_card_table());
    outcome
        .thunk_resolve_card_table
        .mark_source(live_dirty_source)
        .expect("single-tier live dirty card marks");
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);

    let live_state_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("single-tier worker dry-run publishes live remembered set");
    let live_worker_commit = live_state_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live worker commit records");
    assert!(live_state_dry_run.remembered_set_published());
    assert_eq!(live_state_dry_run.card_table_dirty_cards_cleared(), 1);
    assert_eq!(
        outcome.thunk_resolve_remembered_set(),
        live_worker_commit.remembered_set()
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 0);
}

#[test]
fn owned_eval_reports_gc_stress_boundary_promoted_commit_dry_run_bytes() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("lambda evaluates under GC stress");
    let old_base = static_gc_address(0x2000_0000);

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(0),
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), old_base),
        )
        .expect("boundary scan runs promoted owned commit dry-run");

    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.object_copies(), 1);
    assert_eq!(summary.copied_to_nursery(), 0);
    assert_eq!(summary.promoted_to_old(), 1);
    assert!(summary.object_copy_bytes() > 0);
    assert_eq!(summary.copy_to_nursery_bytes(), 0);
    assert_eq!(summary.object_copy_bytes(), summary.promote_to_old_bytes());

    let preflight = dry_run
        .preflights()
        .worker()
        .expect("worker promoted dry-run preflight records");
    assert_eq!(preflight.copy_to_nursery_bytes(), 0);
    assert_eq!(
        summary.promote_to_old_bytes(),
        preflight.promote_to_old_bytes()
    );
    let commit_application = dry_run
        .commit_applications()
        .worker()
        .expect("worker promoted dry-run commit records");
    assert_eq!(commit_application.report().copied_to_nursery(), 0);
    assert_eq!(commit_application.report().promoted_to_old(), 1);
    let object_copy = &commit_application.object_byte_copies()[0];
    let destination_storage = commit_application.destination_storage();
    assert_eq!(destination_storage.copy_report().copied_to_nursery(), 0);
    assert_eq!(destination_storage.copy_report().promoted_to_old(), 1);
    assert_eq!(destination_storage.nursery_reserved_bytes(), 0);
    assert_eq!(
        destination_storage.old_reserved_bytes(),
        preflight
            .relocation_plan()
            .relocation_destinations()
            .placement_plan()
            .old_reserved_bytes()
    );
    assert!(destination_storage.nursery_destination_bytes().is_empty());
    assert_eq!(
        destination_storage.old_destination_bytes(),
        object_copy.source_bytes()
    );
    assert_eq!(
        commit_application.forwarding_slots()[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: old_base,
            generation: HeapGeneration::Old,
        })
    );
    assert_eq!(
        commit_application.references(),
        &[ResolvedValueGeneration::Heap {
            address: old_base,
            generation: HeapGeneration::Old,
        }]
    );
}

#[test]
fn owned_eval_runs_gc_stress_boundary_permanent_commit_dry_run() {
    let ir = lower("\"stress\"");
    let mut outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan runs owned commit dry-run");

    assert_eq!(dry_run.len(), 1);
    assert!(!dry_run.is_empty());
    assert!(dry_run.preflights().worker().is_none());
    assert!(dry_run.reference_writebacks().worker().is_none());
    assert!(dry_run.commit_applications().worker().is_none());
    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.object_copies(), 0);
    assert_eq!(summary.copied_to_nursery(), 0);
    assert_eq!(summary.promoted_to_old(), 0);
    assert_eq!(summary.object_copy_bytes(), 0);
    assert_eq!(summary.copy_to_nursery_bytes(), 0);
    assert_eq!(summary.promote_to_old_bytes(), 0);
    assert_eq!(summary.forwarding_pointers(), 0);
    assert_eq!(summary.reference_rewrites(), 0);
    assert_eq!(summary.root_writebacks(), 0);
    assert_eq!(summary.heap_field_writebacks(), 0);
    assert_eq!(summary.reference_writebacks(), 0);
    assert_eq!(summary.remembered_set_source_edges(), 0);
    assert_eq!(summary.remembered_set_published_edges(), 0);

    let preflight = dry_run
        .preflights()
        .permanent_shared()
        .expect("permanent dry-run preflight records");
    let writeback_application = dry_run
        .reference_writebacks()
        .permanent_shared()
        .expect("permanent dry-run writebacks record");
    let commit_application = dry_run
        .commit_applications()
        .permanent_shared()
        .expect("permanent dry-run commit records");

    assert!(preflight.object_byte_copy_plan().is_empty());
    assert!(preflight.forwarding_slots().is_empty());
    assert!(preflight.reference_writeback_plan().is_empty());
    assert_eq!(writeback_application.report().writebacks(), 0);
    assert!(writeback_application.root_writeback_slots().is_empty());
    assert!(
        writeback_application
            .heap_field_writeback_slots()
            .is_empty()
    );

    let commit_report = commit_application.report();
    assert_eq!(commit_report.object_copies(), 0);
    assert_eq!(commit_report.forwarding_pointers(), 0);
    assert_eq!(commit_report.reference_rewrites(), 0);
    assert!(commit_application.object_byte_copies().is_empty());
    assert_eq!(
        commit_application
            .destination_storage()
            .copy_report()
            .object_copies(),
        0
    );
    assert_eq!(
        commit_application
            .destination_storage()
            .nursery_reserved_bytes(),
        0
    );
    assert_eq!(
        commit_application
            .destination_storage()
            .old_reserved_bytes(),
        0
    );
    assert!(
        commit_application
            .destination_storage()
            .nursery_destination_bytes()
            .is_empty()
    );
    assert!(
        commit_application
            .destination_storage()
            .old_destination_bytes()
            .is_empty()
    );
    assert!(commit_application.forwarding_slots().is_empty());
    assert_eq!(
        commit_application.references(),
        preflight.reference_buffer()
    );
    assert!(commit_application.references().iter().all(|value| matches!(
        value,
        ResolvedValueGeneration::Heap {
            generation: HeapGeneration::Permanent,
            ..
        }
    )));
    assert!(commit_application.remembered_set().is_empty());

    let live_dirty_source = next_dirty_card_source(outcome.thunk_resolve_card_table());
    outcome
        .thunk_resolve_card_table
        .mark_source(live_dirty_source)
        .expect("permanent single-tier live dirty card marks");
    let live_state_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("single-tier permanent dry-run publishes live remembered set");
    assert!(
        live_state_dry_run
            .dry_run()
            .commit_applications()
            .worker()
            .is_none()
    );
    let live_permanent_commit = live_state_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live permanent commit records");
    assert!(live_state_dry_run.remembered_set_published());
    assert_eq!(live_state_dry_run.card_table_dirty_cards_cleared(), 1);
    assert_eq!(
        outcome.thunk_resolve_remembered_set(),
        live_permanent_commit.remembered_set()
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 0);
}

#[test]
fn owned_eval_reports_gc_stress_boundary_heap_field_writeback_slots() {
    let ir = lower("let captured = x: x; in y: captured");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("capturing lambda evaluates under GC stress");
    let nursery_base = static_gc_address(0x1000_0000);

    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("capturing boundary scan builds commit preflight metadata");

    let preflight = preflights.worker().expect("worker preflight records");
    assert_eq!(preflight.root_writeback_slots().len(), 1);
    assert!(!preflight.heap_field_writeback_slots().is_empty());
    let expected_object_copy_bytes = preflight.object_copy_bytes();
    let expected_copy_to_nursery_bytes = preflight.copy_to_nursery_bytes();
    let expected_promote_to_old_bytes = preflight.promote_to_old_bytes();

    let application = preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("mixed boundary writeback slots apply");

    assert_eq!(
        application.report().root_writebacks(),
        application.root_writeback_slots().len()
    );
    assert_eq!(
        application.report().heap_field_writebacks(),
        application.heap_field_writeback_slots().len()
    );
    for (slot, writeback) in application.root_writeback_slots().iter().zip(
        preflight
            .reference_writeback_plan()
            .root_writebacks()
            .writebacks(),
    ) {
        assert_eq!(slot.value(), writeback.replacement());
    }
    for (slot, writeback) in application.heap_field_writeback_slots().iter().zip(
        preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .writebacks(),
    ) {
        assert_eq!(slot.value(), writeback.replacement());
    }
    let commit_application = preflight
        .apply_commit_to_owned_buffers()
        .expect("mixed boundary commit buffers apply");
    assert_eq!(
        commit_application.report().reference_rewrites(),
        application.report().writebacks()
    );
    assert!(
        commit_application
            .object_byte_copies()
            .iter()
            .all(|copy| copy.destination_bytes() == copy.source_bytes())
    );
    let destination_storage = commit_application.destination_storage();
    let storage_report = destination_storage.copy_report();
    assert_eq!(
        storage_report.object_copies(),
        commit_application.report().object_copies()
    );
    assert_eq!(
        storage_report.nursery_payload_bytes() + storage_report.old_payload_bytes(),
        preflight.object_copy_bytes()
    );
    assert!(
        commit_application
            .forwarding_slots()
            .iter()
            .all(|slot| slot.forwarded_value().is_some())
    );

    let dry_run = preflights
        .apply_owned_commit_dry_run()
        .expect("mixed boundary dry-run applies");
    let summary = dry_run.summary();
    assert_eq!(summary.tiers(), 1);
    assert_eq!(summary.root_writebacks(), 1);
    assert!(summary.heap_field_writebacks() > 0);
    assert_eq!(summary.reference_rewrites(), summary.reference_writebacks());
    assert_eq!(summary.object_copy_bytes(), expected_object_copy_bytes);
    assert_eq!(
        summary.copy_to_nursery_bytes(),
        expected_copy_to_nursery_bytes
    );
    assert_eq!(
        summary.promote_to_old_bytes(),
        expected_promote_to_old_bytes
    );
    assert_eq!(
        summary.object_copies(),
        dry_run
            .commit_applications()
            .worker()
            .expect("mixed worker commit records")
            .object_byte_copies()
            .len()
    );
}

#[test]
fn boundary_owned_commit_buffers_publish_retained_remembered_edges() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options.set_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    evaluator
        .heap
        .set_allocation_domain_for_test(thunk_value, HeapAllocationDomain::PermanentShared)
        .expect("test can mark source thunk permanent");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    assert_eq!(forced.tag(), ValueTag::Lambda);

    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(forced)
        .expect("forced value builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let mut outcome = EvalOutcome {
        value: forced,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: evaluator.thunk_resolve_remembered_set,
        thunk_resolve_card_table: evaluator.thunk_resolve_card_table,
        memory_budget_action: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        gc_stress_boundary_scans,
    };
    assert_eq!(outcome.thunk_resolve_remembered_set().len(), 1);

    let nursery_base = static_gc_address(0x1000_0000);
    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("remembered boundary scan builds commit preflight metadata");
    let worker_preflight = preflights.worker().expect("worker preflight records");
    assert_eq!(worker_preflight.card_table().len(), 1);
    let application = preflights
        .worker()
        .expect("worker preflight records")
        .apply_commit_to_owned_buffers()
        .expect("remembered boundary commit buffers apply");

    assert_eq!(application.report().remembered_set_source_edges(), 1);
    assert_eq!(application.report().remembered_set_published_edges(), 1);
    assert_eq!(application.report().card_table_dirty_cards_cleared(), 1);
    assert_eq!(application.remembered_set().len(), 1);
    assert!(application.card_table().is_empty());
    assert_eq!(
        application.remembered_set().edges()[0].source(),
        gc_address(thunk_value)
    );
    assert_eq!(
        application.remembered_set().edges()[0].target(),
        nursery_base
    );

    let dry_run = preflights
        .apply_owned_commit_dry_run()
        .expect("remembered boundary dry-run applies");
    let summary = dry_run.summary();
    let worker_commit = dry_run
        .commit_applications()
        .worker()
        .expect("worker remembered dry-run commit records");
    let permanent_commit = dry_run
        .commit_applications()
        .permanent_shared()
        .expect("permanent empty dry-run commit records");
    let worker_preflight = dry_run
        .preflights()
        .worker()
        .expect("worker remembered dry-run preflight records");
    let permanent_preflight = dry_run
        .preflights()
        .permanent_shared()
        .expect("permanent empty dry-run preflight records");
    assert_eq!(worker_preflight.card_table().len(), 1);
    assert_eq!(permanent_preflight.card_table().len(), 1);

    let worker_report = worker_commit.report();
    let permanent_report = permanent_commit.report();
    assert_eq!(worker_report.card_table_dirty_cards_cleared(), 1);
    assert_eq!(permanent_report.card_table_dirty_cards_cleared(), 1);
    assert!(worker_commit.card_table().is_empty());
    assert!(permanent_commit.card_table().is_empty());

    assert_eq!(summary.tiers(), dry_run.len());
    assert_eq!(
        summary.object_copies(),
        worker_report
            .object_copies()
            .saturating_add(permanent_report.object_copies())
    );
    assert_eq!(
        summary.object_copy_bytes(),
        worker_preflight
            .object_copy_bytes()
            .saturating_add(permanent_preflight.object_copy_bytes())
    );
    assert_eq!(
        summary.copy_to_nursery_bytes(),
        worker_preflight
            .copy_to_nursery_bytes()
            .saturating_add(permanent_preflight.copy_to_nursery_bytes())
    );
    assert_eq!(
        summary.promote_to_old_bytes(),
        worker_preflight
            .promote_to_old_bytes()
            .saturating_add(permanent_preflight.promote_to_old_bytes())
    );
    assert_eq!(
        summary.reference_rewrites(),
        worker_report
            .reference_rewrites()
            .saturating_add(permanent_report.reference_rewrites())
    );
    assert_eq!(
        summary.remembered_set_source_edges(),
        worker_report
            .remembered_set_source_edges()
            .saturating_add(permanent_report.remembered_set_source_edges())
    );
    assert_eq!(
        summary.remembered_set_published_edges(),
        worker_report
            .remembered_set_published_edges()
            .saturating_add(permanent_report.remembered_set_published_edges())
    );
    assert_eq!(
        summary.card_table_dirty_cards_cleared(),
        worker_report
            .card_table_dirty_cards_cleared()
            .saturating_add(permanent_report.card_table_dirty_cards_cleared())
    );
    assert!(summary.remembered_set_source_edges() > 0);
    assert!(summary.remembered_set_published_edges() > 0);

    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    let extra_card_source = next_dirty_card_source(outcome.thunk_resolve_card_table());
    outcome
        .thunk_resolve_card_table
        .mark_source(extra_card_source)
        .expect("extra live dirty card marks");
    assert_eq!(outcome.thunk_resolve_card_table().len(), 2);
    let remembered_set_before_reject = outcome.thunk_resolve_remembered_set().clone();
    let card_table_before_reject = outcome.thunk_resolve_card_table().clone();
    let publish_error = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect_err("sibling boundary preflights cannot publish one live remembered set");
    assert_eq!(
        publish_error,
        EvalHeapError::BoundaryMinorGcLiveRememberedSetMultipleTiers { tiers: 2 }
    );
    assert_eq!(
        outcome.thunk_resolve_remembered_set(),
        &remembered_set_before_reject
    );
    assert_eq!(
        outcome.thunk_resolve_card_table(),
        &card_table_before_reject
    );

    let live_card_table_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("remembered boundary dry-run clears outcome card table");
    assert_eq!(
        live_card_table_dry_run
            .dry_run()
            .summary()
            .card_table_dirty_cards_cleared(),
        live_card_table_dry_run
            .card_table_dirty_cards_cleared()
            .saturating_mul(live_card_table_dry_run.dry_run().len())
    );
    assert_eq!(live_card_table_dry_run.card_table_dirty_cards_cleared(), 2);
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn boundary_owned_commit_buffers_publish_dirty_old_field_rescan_edges() {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    );
    let child = evaluator.eval_root().expect("lambda evaluates");
    let permanent_parent = evaluator
        .heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    evaluator
        .heap
        .set_allocation_domain_for_test(permanent_parent, HeapAllocationDomain::PermanentShared)
        .expect("test can mark parent permanent");
    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(permanent_parent)
        .expect("permanent parent builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let mut card_table = GcCardTable::default();
    card_table
        .mark_source(gc_address(permanent_parent))
        .expect("permanent parent card marks");
    let mut outcome = EvalOutcome {
        value: permanent_parent,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: RememberedSet::new(),
        thunk_resolve_card_table: card_table,
        memory_budget_action: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        gc_stress_boundary_scans,
    };

    let nursery_base = static_gc_address(0x1000_0000);
    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty old-field boundary scan builds commit preflight metadata");
    let worker_preflight = preflights.worker().expect("worker preflight records");

    assert_eq!(outcome.thunk_resolve_remembered_set().len(), 0);
    assert_eq!(worker_preflight.card_table().len(), 1);
    assert_eq!(
        worker_preflight
            .relocation_plan()
            .minor_gc_plan()
            .plan()
            .survivors()[0]
            .address(),
        gc_address(child)
    );
    assert_eq!(
        worker_preflight
            .reference_writeback_plan()
            .heap_field_writebacks()
            .len(),
        1
    );
    assert!(worker_preflight.root_writeback_slots().is_empty());
    assert_eq!(worker_preflight.heap_field_writeback_slots().len(), 1);
    assert_eq!(
        worker_preflight.heap_field_writeback_slots()[0].validation_object(),
        gc_address(permanent_parent)
    );

    let application = worker_preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("dirty old-field boundary writeback slots apply");
    assert_eq!(application.report().root_writebacks(), 0);
    assert_eq!(application.report().heap_field_writebacks(), 1);
    assert_eq!(
        application.heap_field_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );

    let commit_application = worker_preflight
        .apply_commit_to_owned_buffers()
        .expect("dirty old-field boundary commit buffers apply");
    assert_eq!(commit_application.report().remembered_set_source_edges(), 0);
    assert_eq!(
        commit_application.report().remembered_set_published_edges(),
        1
    );
    assert_eq!(
        commit_application.report().card_table_dirty_cards_cleared(),
        1
    );
    assert_eq!(commit_application.remembered_set().len(), 1);
    assert_eq!(
        commit_application.remembered_set().edges()[0].source(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        commit_application.remembered_set().edges()[0].target(),
        nursery_base
    );
    assert!(commit_application.card_table().is_empty());

    let dry_run = preflights
        .apply_owned_commit_dry_run()
        .expect("dirty old-field boundary dry-run applies");
    let summary = dry_run.summary();
    let dry_worker_commit = dry_run
        .commit_applications()
        .worker()
        .expect("worker dirty old-field dry-run commit records");
    let dry_permanent_commit = dry_run
        .commit_applications()
        .permanent_shared()
        .expect("permanent dirty old-field dry-run commit records");
    let dry_worker_writebacks = dry_run
        .reference_writebacks()
        .worker()
        .expect("worker dirty old-field writebacks record");
    let dry_permanent_writebacks = dry_run
        .reference_writebacks()
        .permanent_shared()
        .expect("permanent dirty old-field writebacks record");
    let dry_worker_report = dry_worker_commit.report();
    let dry_permanent_report = dry_permanent_commit.report();

    assert_eq!(summary.tiers(), dry_run.len());
    assert_eq!(
        summary.root_writebacks(),
        dry_worker_writebacks
            .report()
            .root_writebacks()
            .saturating_add(dry_permanent_writebacks.report().root_writebacks())
    );
    assert_eq!(
        summary.heap_field_writebacks(),
        dry_worker_writebacks
            .report()
            .heap_field_writebacks()
            .saturating_add(dry_permanent_writebacks.report().heap_field_writebacks())
    );
    assert_eq!(
        summary.reference_rewrites(),
        dry_worker_report
            .reference_rewrites()
            .saturating_add(dry_permanent_report.reference_rewrites())
    );
    assert_eq!(
        summary.remembered_set_source_edges(),
        dry_worker_report
            .remembered_set_source_edges()
            .saturating_add(dry_permanent_report.remembered_set_source_edges())
    );
    assert_eq!(
        summary.remembered_set_published_edges(),
        dry_worker_report
            .remembered_set_published_edges()
            .saturating_add(dry_permanent_report.remembered_set_published_edges())
    );
    assert_eq!(
        summary.card_table_dirty_cards_cleared(),
        dry_worker_report
            .card_table_dirty_cards_cleared()
            .saturating_add(dry_permanent_report.card_table_dirty_cards_cleared())
    );
    assert_eq!(dry_worker_report.remembered_set_source_edges(), 0);
    assert_eq!(dry_worker_report.remembered_set_published_edges(), 1);

    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    let live_card_table_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty old-field boundary dry-run clears outcome card table");
    assert_eq!(
        live_card_table_dry_run
            .dry_run()
            .summary()
            .card_table_dirty_cards_cleared(),
        summary.card_table_dirty_cards_cleared()
    );
    assert_eq!(live_card_table_dry_run.card_table_dirty_cards_cleared(), 1);
    assert!(outcome.thunk_resolve_card_table().is_empty());
}

#[test]
fn boundary_minor_gc_plans_reject_remembered_edge_without_dirty_card() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options.set_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    evaluator
        .heap
        .set_allocation_domain_for_test(thunk_value, HeapAllocationDomain::PermanentShared)
        .expect("test can mark source thunk permanent");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(forced)
        .expect("forced value builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let remembered_set = evaluator.thunk_resolve_remembered_set;
    let edge = remembered_set.edges()[0];
    let outcome = EvalOutcome {
        value: forced,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: remembered_set,
        thunk_resolve_card_table: GcCardTable::default(),
        memory_budget_action: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        gc_stress_boundary_scans,
    };

    let error = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect_err("boundary planning requires dirty remembered source card");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollDirtyCard {
            source_address: edge.source(),
            target_address: edge.target(),
            card_index: outcome
                .thunk_resolve_card_table()
                .snapshot()
                .card_index_for_source(edge.source()),
        }
    );
}

#[test]
fn boundary_live_card_table_clear_waits_for_successful_commit_dry_run() {
    let ir = lower("{ a = x: x; }");
    let a = symbol_for(&ir, b"a");
    let mut options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
    options.set_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    evaluator
        .heap
        .set_allocation_domain_for_test(thunk_value, HeapAllocationDomain::PermanentShared)
        .expect("test can mark source thunk permanent");
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    let gc_stress_boundary_scans = evaluator
        .gc_stress_boundary_scans(forced)
        .expect("forced value builds boundary scans");
    let derivations = evaluator
        .derivation_snapshot()
        .expect("derivation snapshot succeeds");
    let stats = evaluator.stats_snapshot();
    let remembered_set = evaluator.thunk_resolve_remembered_set;
    let edge = remembered_set.edges()[0];
    let wrong_card_source = static_gc_address(0x4000_0000);
    let mut wrong_card_table = GcCardTable::default();
    wrong_card_table
        .mark_source(wrong_card_source)
        .expect("wrong card marks");
    let mut outcome = EvalOutcome {
        value: forced,
        heap: evaluator.heap,
        stats,
        attr_telemetry: evaluator.attr_telemetry,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        impure_input_trace: evaluator.impure_input_trace,
        impure_input_trace_complete: evaluator.impure_input_trace_complete,
        persist_force_cache_hit_keys: evaluator.persist_force_cache_hit_keys,
        derivations,
        thunk_resolve_remembered_set: remembered_set,
        thunk_resolve_card_table: wrong_card_table,
        memory_budget_action: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        gc_stress_boundary_scans,
    };

    let error = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect_err("missing dirty source card rejects before live clear");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollDirtyCard {
            source_address: edge.source(),
            target_address: edge.target(),
            card_index: outcome
                .thunk_resolve_card_table()
                .snapshot()
                .card_index_for_source(edge.source()),
        }
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards()[0].source(),
        wrong_card_source
    );
}

#[test]
fn owned_eval_reports_gc_stress_boundary_permanent_commit_preflight() {
    let ir = lower("\"stress\"");
    let outcome = eval_whnf_owned_with_options(
        &ir,
        TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint()),
    )
    .expect("string evaluates under GC stress");

    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("permanent boundary scan builds commit preflight metadata");

    assert_eq!(preflights.len(), 1);
    assert!(preflights.worker().is_none());
    let preflight = preflights
        .permanent_shared()
        .expect("permanent preflight records");
    assert!(
        preflight
            .relocation_plan()
            .minor_gc_plan()
            .plan()
            .is_empty()
    );
    assert!(preflight.object_byte_copy_plan().is_empty());
    assert!(preflight.forwarding_slots().is_empty());
    assert_eq!(
        preflight.reference_buffer(),
        preflight
            .relocation_plan()
            .minor_gc_plan()
            .reference_values()
            .collect::<Vec<_>>()
    );
    assert!(preflight.reference_buffer().iter().all(|value| matches!(
        value,
        ResolvedValueGeneration::Heap {
            generation: HeapGeneration::Permanent,
            ..
        }
    )));
    assert!(preflight.reference_writeback_plan().is_empty());
    assert!(preflight.root_writeback_slots().is_empty());
    assert!(preflight.heap_field_writeback_slots().is_empty());
    let application = preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("empty boundary writeback slots apply");
    assert_eq!(application.report().writebacks(), 0);
    assert!(application.root_writeback_slots().is_empty());
    assert!(application.heap_field_writeback_slots().is_empty());
    let commit_application = preflight
        .apply_commit_to_owned_buffers()
        .expect("empty boundary commit buffers apply");
    assert_eq!(commit_application.report().object_copies(), 0);
    assert_eq!(commit_application.report().forwarding_pointers(), 0);
    assert_eq!(commit_application.report().reference_rewrites(), 0);
    assert!(commit_application.object_byte_copies().is_empty());
    assert_eq!(
        commit_application
            .destination_storage()
            .copy_report()
            .object_copies(),
        0
    );
    assert!(commit_application.forwarding_slots().is_empty());
    assert_eq!(
        commit_application.references(),
        preflight.reference_buffer()
    );
    assert!(commit_application.remembered_set().is_empty());

    let applications = preflights
        .apply_reference_writebacks_to_owned_slots()
        .expect("permanent boundary preflight applies owned writeback slots");
    assert_eq!(applications.len(), 1);
    assert!(applications.worker().is_none());
    assert_eq!(applications.permanent_shared(), Some(&application));
    let commit_applications = preflights
        .apply_commits_to_owned_buffers()
        .expect("permanent boundary preflight applies owned commit buffers");
    assert_eq!(commit_applications.len(), 1);
    assert!(commit_applications.worker().is_none());
    assert_eq!(
        commit_applications.permanent_shared(),
        Some(&commit_application)
    );
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_commit_preflights() {
    let ir = lower("x: x");
    let mut outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty commit preflight metadata");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(preflights.is_empty());
    let applications = preflights
        .apply_reference_writebacks_to_owned_slots()
        .expect("empty boundary preflights produce empty writeback application");
    assert!(applications.is_empty());
    let commit_applications = preflights
        .apply_commits_to_owned_buffers()
        .expect("empty boundary preflights produce empty commit application");
    assert!(commit_applications.is_empty());

    let dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty dry-run application");
    assert!(dry_run.is_empty());
    assert_eq!(dry_run.len(), 0);
    assert!(dry_run.preflights().is_empty());
    assert!(dry_run.reference_writebacks().is_empty());
    assert!(dry_run.commit_applications().is_empty());

    let unrelated_dirty_source = static_gc_address(0x1000_0000);
    outcome
        .thunk_resolve_card_table
        .mark_source(unrelated_dirty_source)
        .expect("unrelated dirty card marks");
    let live_card_table_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run succeeds without clearing live cards");
    assert!(live_card_table_dry_run.dry_run().is_empty());
    assert_eq!(live_card_table_dry_run.card_table_dirty_cards_cleared(), 0);
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    assert_eq!(
        outcome.thunk_resolve_card_table().dirty_cards()[0].source(),
        unrelated_dirty_source
    );
    let remembered_set_before_empty = outcome.thunk_resolve_remembered_set().clone();
    let empty_live_state_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run leaves live GC metadata alone");
    assert!(empty_live_state_dry_run.dry_run().is_empty());
    assert!(!empty_live_state_dry_run.remembered_set_published());
    assert_eq!(empty_live_state_dry_run.card_table_dirty_cards_cleared(), 0);
    assert_eq!(
        outcome.thunk_resolve_remembered_set(),
        &remembered_set_before_empty
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_relocation_destinations() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let destinations = outcome
        .gc_stress_boundary_minor_gc_relocation_destinations(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty destinations");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(destinations.is_empty());
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_relocation_plans() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_relocation_plans(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary scans produce empty paired plans");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(plans.is_empty());
}

#[test]
fn owned_eval_without_gc_stress_has_no_boundary_minor_gc_plans() {
    let ir = lower("x: x");
    let outcome = eval_whnf_owned(&ir).expect("lambda evaluates without GC stress");
    let plans = outcome
        .gc_stress_boundary_minor_gc_plans(MinorGcPromotionPolicy::new(2))
        .expect("empty boundary scans produce empty plans");

    assert!(outcome.gc_stress_boundary_scans().is_empty());
    assert!(plans.is_empty());
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
