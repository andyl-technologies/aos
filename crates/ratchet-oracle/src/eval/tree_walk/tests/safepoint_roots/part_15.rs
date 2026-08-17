//! Split-out tests (part_15). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    let edge = RememberedEdge::new(gc_address(thunk_value), gc_address(forced));
    assert!(
        remembered_set.edges().contains(&edge),
        "thunk-resolution write barrier records forced value edge"
    );
    let remembered_set = remembered_set_with_only_edge(&remembered_set, edge);
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
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans,
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
    let edge = RememberedEdge::new(gc_address(thunk_value), gc_address(forced));
    assert!(
        remembered_set.edges().contains(&edge),
        "thunk-resolution write barrier records forced value edge"
    );
    let remembered_set = remembered_set_with_only_edge(&remembered_set, edge);
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
        tier_b_transition_admission_report: None,
        cheap_memory_budget_plan: None,
        cheap_memory_advice_report: None,
        cold_hash_consed_value_materialization: None,
        gc_stress_boundary_scans,
        gc_stress_boundary_minor_gc_reference_writebacks:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default(),
        gc_stress_boundary_minor_gc_forwarding_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings::default(),
        gc_stress_boundary_minor_gc_destination_storage:
            EvalGcStressBoundaryMinorGcLiveDestinationStorage::default(),
        gc_stress_boundary_minor_gc_object_generations:
            EvalGcStressBoundaryMinorGcLiveObjectGenerations::default(),
        gc_stress_boundary_minor_gc_writeback_destination_bindings:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default(),
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
    let mut outcome = eval_whnf_owned_with_options(
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
    assert!(preflight.root_value_writeback_slots().is_empty());
    assert!(preflight.heap_field_writeback_slots().is_empty());
    let application = preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("empty boundary writeback slots apply");
    assert_eq!(application.report().writebacks(), 0);
    assert!(application.root_writeback_slots().is_empty());
    assert!(application.root_value_writeback_slots().is_empty());
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

    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    let live_writeback_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("no-writeback boundary dry-run is a live side-table no-op");
    assert_eq!(live_writeback_dry_run.dry_run().len(), 1);
    assert_eq!(
        live_writeback_dry_run
            .dry_run()
            .reference_writebacks()
            .permanent_shared()
            .expect("permanent no-writeback application records")
            .report()
            .writebacks(),
        0
    );
    assert_eq!(live_writeback_dry_run.reference_writebacks_installed(), 0);
    assert_eq!(
        live_writeback_dry_run
            .reference_writeback_install_report()
            .tiers(),
        0
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    let repeat_noop = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("repeated no-writeback live side-table run stays a no-op");
    assert_eq!(repeat_noop.reference_writebacks_installed(), 0);
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
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
    let empty_live_forwarding_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run leaves live forwarding alone");
    assert!(empty_live_forwarding_dry_run.dry_run().is_empty());
    assert_eq!(
        empty_live_forwarding_dry_run.forwarding_pointers_installed(),
        0
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_forwarding_header_write_plan()
            .expect("empty boundary has no forwarding header writes")
            .is_empty()
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_root_writeback_write_plan()
            .expect("empty boundary has no root writeback writes")
            .is_empty()
    );
    let empty_live_destination_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("empty boundary dry run leaves live destination storage alone");
    assert!(empty_live_destination_dry_run.dry_run().is_empty());
    assert_eq!(empty_live_destination_dry_run.object_copies_installed(), 0);
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_destination_storage()
            .is_empty()
    );
    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
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

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
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
