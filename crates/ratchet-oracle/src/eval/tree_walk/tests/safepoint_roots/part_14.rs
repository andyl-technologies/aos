//! Split-out tests (part_14). See parent module.

use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn boundary_owned_commit_buffers_publish_retained_remembered_edges() {
    let (mut outcome, thunk_value) = boundary_remembered_edge_outcome();
    assert_eq!(outcome.value().tag(), ValueTag::Lambda);
    let _retained_edge = retain_only_thunk_resolve_edge(&mut outcome, thunk_value);

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

    let (mut forwarding_outcome, forwarding_thunk_value) = boundary_remembered_edge_outcome();
    let _forwarding_edge =
        retain_only_thunk_resolve_edge(&mut forwarding_outcome, forwarding_thunk_value);
    let live_forwarding_dry_run = forwarding_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("sibling boundary preflights install merged live forwarding");
    let live_forwarding_worker = live_forwarding_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live forwarding worker commit records");
    let live_forwarding_permanent = live_forwarding_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live forwarding permanent commit records");
    let mut expected_forwarding = Vec::new();
    for slot in live_forwarding_worker
        .forwarding_slots()
        .iter()
        .chain(live_forwarding_permanent.forwarding_slots())
    {
        let Some(forwarded) = slot.forwarded_value() else {
            continue;
        };
        if let Some((_, existing)) = expected_forwarding
            .iter()
            .find(|(source, _)| *source == slot.source())
        {
            assert_eq!(*existing, forwarded);
            continue;
        }
        expected_forwarding.push((slot.source(), forwarded));
    }
    assert!(!live_forwarding_worker.forwarding_slots().is_empty());
    assert!(!live_forwarding_permanent.forwarding_slots().is_empty());
    assert!(!expected_forwarding.is_empty());
    assert_eq!(
        live_forwarding_dry_run.forwarding_pointers_installed(),
        expected_forwarding.len()
    );
    for (source, forwarded) in expected_forwarding {
        assert_eq!(
            forwarding_outcome
                .heap()
                .minor_gc_forwarding_value_at(source)
                .expect("merged forwarding source remains known"),
            Some(forwarded)
        );
    }

    let (mut destination_outcome, destination_thunk_value) = boundary_remembered_edge_outcome();
    let _destination_edge =
        retain_only_thunk_resolve_edge(&mut destination_outcome, destination_thunk_value);
    let live_destination_dry_run = destination_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("sibling boundary preflights install merged live destination bytes");
    let live_destination_worker = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live destination worker commit records");
    let live_destination_permanent = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live destination permanent commit records");
    let mut expected_destination_objects: Vec<(
        AllocationCollectorPollObjectByteCopyRequest,
        Vec<u8>,
    )> = Vec::new();
    let mut overlapping_destination_sources = 0usize;
    for object_copy in live_destination_worker
        .object_byte_copies()
        .iter()
        .chain(live_destination_permanent.object_byte_copies())
    {
        if let Some((expected_request, expected_bytes)) = expected_destination_objects
            .iter()
            .find(|(request, _)| request.source() == object_copy.request().source())
        {
            overlapping_destination_sources = overlapping_destination_sources.saturating_add(1);
            assert_eq!(*expected_request, object_copy.request());
            assert_eq!(expected_bytes.as_slice(), object_copy.destination_bytes());
            continue;
        }
        expected_destination_objects.push((
            object_copy.request(),
            object_copy.destination_bytes().to_vec(),
        ));
    }
    let live_destination_storage =
        destination_outcome.gc_stress_boundary_minor_gc_destination_storage();
    assert!(!expected_destination_objects.is_empty());
    assert!(overlapping_destination_sources > 0);
    assert_eq!(
        live_destination_dry_run.object_copies_installed(),
        expected_destination_objects.len()
    );
    assert_eq!(
        live_destination_storage.len(),
        expected_destination_objects.len()
    );
    for installed in live_destination_storage.object_bytes() {
        let (_, expected_bytes) = expected_destination_objects
            .iter()
            .find(|(request, _)| *request == installed.request())
            .expect("installed destination object has expected dry-run source");
        assert_eq!(installed.destination_bytes(), expected_bytes.as_slice());
    }

    let (mut merge_outcome, merge_thunk_value) = boundary_remembered_edge_outcome();
    let _merge_edge = retain_only_thunk_resolve_edge(&mut merge_outcome, merge_thunk_value);
    let extra_card_source = next_dirty_card_source(merge_outcome.thunk_resolve_card_table());
    merge_outcome
        .thunk_resolve_card_table
        .mark_source(extra_card_source)
        .expect("extra merge live dirty card marks");
    assert_eq!(merge_outcome.thunk_resolve_card_table().len(), 2);
    let live_remembered_set_dry_run = merge_outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("sibling boundary preflights merge one live remembered set");
    assert!(live_remembered_set_dry_run.remembered_set_published());
    assert_eq!(
        live_remembered_set_dry_run.card_table_dirty_cards_cleared(),
        2
    );
    assert!(merge_outcome.thunk_resolve_card_table().is_empty());
    let live_worker_commit = live_remembered_set_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("live worker commit records");
    let live_permanent_commit = live_remembered_set_dry_run
        .dry_run()
        .commit_applications()
        .permanent_shared()
        .expect("live permanent commit records");
    let mut overlapping_relocations = 0usize;
    let mut merged_relocations = Vec::new();
    for worker_slot in live_worker_commit.forwarding_slots() {
        if let Some(forwarded) = worker_slot.forwarded_value() {
            merged_relocations.push((worker_slot.source(), forwarded));
        }
        for permanent_slot in live_permanent_commit.forwarding_slots() {
            if worker_slot.source() == permanent_slot.source() {
                overlapping_relocations = overlapping_relocations.saturating_add(1);
                assert_eq!(
                    worker_slot.forwarded_value(),
                    permanent_slot.forwarded_value()
                );
            }
        }
    }
    for permanent_slot in live_permanent_commit.forwarding_slots() {
        let Some(forwarded) = permanent_slot.forwarded_value() else {
            continue;
        };
        if merged_relocations
            .iter()
            .any(|(source, _)| *source == permanent_slot.source())
        {
            continue;
        }
        if let Some(forwarded_address) = resolved_heap_destination_address(forwarded) {
            assert!(!merged_relocations.iter().any(|(_, destination)| {
                resolved_heap_destination_address(*destination) == Some(forwarded_address)
            }));
        }
        merged_relocations.push((permanent_slot.source(), forwarded));
    }
    for (_, destination) in &merged_relocations {
        let ResolvedValueGeneration::Heap { address, .. } = destination else {
            continue;
        };
        assert!(
            !merged_relocations
                .iter()
                .any(|(source, _)| source == address)
        );
    }
    assert!(overlapping_relocations > 0);
    let mut expected_merged_remembered_set =
        RememberedSet::with_epoch(live_worker_commit.remembered_set().epoch());
    for edge in live_worker_commit.remembered_set().edges() {
        expected_merged_remembered_set
            .record(*edge)
            .expect("worker edge records in expected merge");
    }
    for edge in live_permanent_commit.remembered_set().edges() {
        expected_merged_remembered_set
            .record(*edge)
            .expect("permanent edge records in expected merge");
    }
    assert_eq!(
        merge_outcome.thunk_resolve_remembered_set(),
        &expected_merged_remembered_set
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn boundary_owned_commit_buffers_publish_dirty_permanent_field_rescan_edges() {
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

    let nursery_base = static_gc_address(0x1000_0000);
    let preflights = outcome
        .gc_stress_boundary_minor_gc_commit_preflights(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary scan builds commit preflight metadata");
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
    assert!(worker_preflight.root_value_writeback_slots().is_empty());
    assert_eq!(worker_preflight.heap_field_writeback_slots().len(), 1);
    assert_eq!(
        worker_preflight.heap_field_writeback_slots()[0].validation_object(),
        gc_address(permanent_parent)
    );

    let application = worker_preflight
        .apply_reference_writebacks_to_owned_slots()
        .expect("dirty permanent-field boundary writeback slots apply");
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
        .expect("dirty permanent-field boundary commit buffers apply");
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
        .expect("dirty permanent-field boundary dry-run applies");
    let summary = dry_run.summary();
    let dry_worker_commit = dry_run
        .commit_applications()
        .worker()
        .expect("worker dirty permanent-field dry-run commit records");
    let dry_permanent_commit = dry_run
        .commit_applications()
        .permanent_shared()
        .expect("permanent dirty permanent-field dry-run commit records");
    let dry_worker_writebacks = dry_run
        .reference_writebacks()
        .worker()
        .expect("worker dirty permanent-field writebacks record");
    let dry_permanent_writebacks = dry_run
        .reference_writebacks()
        .permanent_shared()
        .expect("permanent dirty permanent-field writebacks record");
    let dry_worker_report = dry_worker_commit.report();
    let dry_permanent_report = dry_permanent_commit.report();

    assert_eq!(summary.tiers(), dry_run.len());
    let canonical_heap_field_writebacks = 1usize;
    let canonical_writeback_destination_bindings = summary
        .root_writebacks()
        .saturating_add(canonical_heap_field_writebacks);
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
    assert_eq!(summary.heap_field_writebacks(), 2);
    assert_eq!(dry_worker_report.remembered_set_source_edges(), 0);
    assert_eq!(dry_worker_report.remembered_set_published_edges(), 1);

    assert!(
        outcome
            .gc_stress_boundary_minor_gc_reference_writebacks()
            .is_empty()
    );
    let live_writeback_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary installs live writeback metadata");
    assert_eq!(
        live_writeback_dry_run.reference_writebacks_installed(),
        summary.reference_writebacks()
    );
    assert_eq!(
        live_writeback_dry_run
            .reference_writeback_install_report()
            .heap_field_writebacks(),
        summary.heap_field_writebacks()
    );
    let live_writebacks = outcome.gc_stress_boundary_minor_gc_reference_writebacks();
    let live_worker_writebacks = live_writebacks
        .worker()
        .expect("dirty permanent-field worker writebacks install");
    assert_eq!(live_writebacks.len(), dry_run.reference_writebacks().len());
    assert_eq!(
        live_writebacks.install_report().writebacks(),
        summary.reference_writebacks()
    );
    assert_eq!(
        live_worker_writebacks.heap_field_writeback_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    let binding_err = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_destination_bindings()
        .expect_err("destination binding requires installed destination bytes");
    assert!(matches!(
        binding_err,
        EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementMissing {
            replacement,
            ..
        } if replacement == nursery_base
    ));
    let live_destination_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary installs live destination storage");
    let live_destination_storage = outcome.gc_stress_boundary_minor_gc_destination_storage();
    let live_object_copy = live_destination_dry_run
        .dry_run()
        .commit_applications()
        .worker()
        .expect("worker destination storage records object copy")
        .object_byte_copies()[0]
        .clone();
    assert_eq!(live_destination_storage.len(), 1);
    assert_eq!(
        live_destination_storage.object_bytes()[0].request(),
        live_object_copy.request()
    );
    let field_bindings = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_destination_bindings()
        .expect("heap-field writeback destination bindings validate");
    assert_eq!(field_bindings.len(), canonical_heap_field_writebacks);
    let dirty_field_binding = field_bindings
        .iter()
        .find(|binding| {
            binding.validation_object() == gc_address(permanent_parent)
                && binding.writeback_object() == gc_address(permanent_parent)
        })
        .expect("dirty permanent-field binding records");
    assert_eq!(
        dirty_field_binding.allocation_domain(),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        dirty_field_binding.validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        dirty_field_binding.writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(dirty_field_binding.field_index(), 0);
    assert_eq!(
        dirty_field_binding.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(dirty_field_binding.replacement_destination(), nursery_base);
    assert_eq!(
        dirty_field_binding.replacement_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        dirty_field_binding.replacement_request(),
        live_object_copy.request()
    );
    assert_eq!(
        dirty_field_binding.replacement_destination_bytes(),
        live_object_copy.destination_bytes()
    );
    assert_eq!(dirty_field_binding.writeback_object_request(), None);
    assert_eq!(
        dirty_field_binding.writeback_object_destination_bytes(),
        None
    );
    assert!(
        outcome
            .gc_stress_boundary_minor_gc_writeback_destination_bindings()
            .is_empty()
    );
    let live_writeback_binding_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_writeback_destination_bindings(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary installs live writeback destination bindings");
    assert_eq!(
        live_writeback_binding_dry_run.writeback_destination_bindings_installed(),
        canonical_writeback_destination_bindings
    );
    assert_eq!(
        live_writeback_binding_dry_run.heap_field_writeback_destination_bindings_installed(),
        canonical_heap_field_writebacks
    );
    let live_writeback_destination_bindings =
        outcome.gc_stress_boundary_minor_gc_writeback_destination_bindings();
    assert_eq!(
        live_writeback_destination_bindings.len(),
        canonical_writeback_destination_bindings
    );
    assert_eq!(
        live_writeback_destination_bindings
            .install_report()
            .heap_field_writeback_bindings(),
        canonical_heap_field_writebacks
    );
    let installed_dirty_field_binding = live_writeback_destination_bindings
        .heap_field_writeback_bindings()
        .iter()
        .find(|binding| {
            binding.validation_object() == gc_address(permanent_parent)
                && binding.writeback_object() == gc_address(permanent_parent)
        })
        .expect("installed dirty permanent-field binding records");
    assert_eq!(installed_dirty_field_binding, dirty_field_binding);
    let heap_field_writeback_write_plan = outcome
        .gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()
        .expect("heap-field writeback write plan validates installed live metadata");
    assert_eq!(
        heap_field_writeback_write_plan.len(),
        canonical_heap_field_writebacks
    );
    assert_eq!(
        heap_field_writeback_write_plan.report().fields(),
        canonical_heap_field_writebacks
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .copied_replacements_to_nursery(),
        canonical_heap_field_writebacks
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .promoted_replacements_to_old(),
        0
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .replacement_payload_bytes(),
        live_object_copy
            .destination_bytes()
            .len()
            .saturating_mul(canonical_heap_field_writebacks)
    );
    assert_eq!(
        heap_field_writeback_write_plan
            .report()
            .writeback_object_payload_bytes(),
        0
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].allocation_domain(),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(heap_field_writeback_write_plan.writes()[0].field_index(), 0);
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_destination(),
        nursery_base
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_metadata(),
        ResolvedValueGeneration::Heap {
            address: nursery_base,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_request(),
        live_object_copy.request()
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].replacement_destination_bytes(),
        live_object_copy.destination_bytes()
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].writeback_object_request(),
        None
    );
    assert_eq!(
        heap_field_writeback_write_plan.writes()[0].writeback_object_destination_bytes(),
        None
    );

    assert_eq!(outcome.thunk_resolve_card_table().len(), 1);
    let live_card_table_dry_run = outcome
        .gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
            MinorGcPromotionPolicy::new(2),
            MinorGcDestinationBases::new(nursery_base, static_gc_address(0x2000_0000)),
        )
        .expect("dirty permanent-field boundary dry-run clears outcome card table");
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
